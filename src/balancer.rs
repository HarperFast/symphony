use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_ns() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or(Duration::ZERO)
		.as_nanos() as u64
}

/// Cached value of sysconf(_SC_CLK_TCK) — usually 100 on Linux.
fn clk_tck_hz() -> u64 {
	static CLK_TCK: OnceLock<u64> = OnceLock::new();
	*CLK_TCK.get_or_init(|| {
		let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
		if v > 0 {
			v as u64
		} else {
			100
		}
	})
}

/// Read the combined utime+stime (in clock ticks) for a specific thread
/// from `/proc/{pid}/task/{tid}/stat`.
/// Returns `None` on any parse or I/O error (process gone, non-Linux, etc.).
fn read_thread_cpu_ticks(pid: u32, tid: u32) -> Option<u64> {
	let content = std::fs::read_to_string(format!("/proc/{pid}/task/{tid}/stat")).ok()?;
	// The comm field (field 2) is wrapped in parentheses and may itself contain
	// '(' or ')' — find the *last* ')' to locate the end of the comm field.
	let rparen = content.rfind(')')?;
	let after_comm = content[rparen + 1..].trim_start();
	let fields: Vec<&str> = after_comm.split_whitespace().collect();
	// After comm: state(0) ppid(1) pgrp(2) sess(3) tty(4) tpgid(5) flags(6)
	//   minflt(7) cminflt(8) majflt(9) cmajflt(10) utime(11) stime(12) …
	let utime: u64 = fields.get(11)?.parse().ok()?;
	let stime: u64 = fields.get(12)?.parse().ok()?;
	Some(utime + stime)
}

// ── Public slot specification ─────────────────────────────────────────────────

/// Caller-provided description of one UDS socket slot.
pub struct UdsSlotSpec {
	pub path: String,
	/// Linux process ID of the worker serving this socket (optional).
	pub pid: Option<u32>,
	/// Linux thread ID of the worker serving this socket (optional).
	pub tid: Option<u32>,
}

// ── Local upstream health (failover routes only) ─────────────────────────────

/// Whether one local upstream endpoint (a UDS slot, or a TCP destination) is refusing connections.
/// Shared by `Arc` across route-table rebuilds, so a connection still running on the previous table
/// marks the state the live table reads.
#[derive(Default)]
pub struct SlotHealth {
	/// Monotonic ns (`protection::now_ns`) of the latest refusal; 0 = accepting.
	refused_at_ns: AtomicU64,
}

impl SlotHealth {
	pub fn refusing(&self) -> bool {
		self.refused_at_ns.load(Ordering::Relaxed) != 0
	}

	pub fn refused_at(&self) -> u64 {
		self.refused_at_ns.load(Ordering::Relaxed)
	}

	pub fn mark_refused(&self) {
		self.refused_at_ns
			.store(crate::protection::now_ns().max(1), Ordering::Relaxed);
	}

	pub fn mark_accepting(&self) {
		self.refused_at_ns.store(0, Ordering::Relaxed);
	}

	/// Clears the refusal a probe observed before it connected. A refusal recorded after that
	/// observation has a different timestamp and survives.
	pub fn clear_if_unchanged(&self, observed: u64) -> bool {
		self.refused_at_ns
			.compare_exchange(observed, 0, Ordering::Relaxed, Ordering::Relaxed)
			.is_ok()
	}
}

// ── Internal slot state ───────────────────────────────────────────────────────

struct UdsSlot {
	path: Arc<str>,
	active: AtomicU32,
	/// `Some` only on a failover route's balancer: refusing slots are skipped by `pick()` and
	/// cleared by the failover probe. Without a probe a skipped slot would never be re-tested.
	health: Option<Arc<SlotHealth>>,
	// CPU monitoring — all zero / None when pid/tid absent.
	pid: Option<u32>,
	tid: Option<u32>,
	/// Measured CPU utilisation in permille (0–1000 = 0–100 %).
	/// Updated by `update_cpu_stats()`; default 0 → pure least-connections.
	cpu_util_permille: AtomicU32,
	/// utime+stime (clock ticks) at the time of the last sample.
	last_cpu_ticks: AtomicU64,
	/// Wall-clock nanoseconds at the time of the last sample (0 = never sampled).
	last_sample_ns: AtomicU64,
}

impl UdsSlot {
	fn refusing(&self) -> bool {
		self.health.as_ref().is_some_and(|h| h.refusing())
	}

	/// Combined selection score: active connections dominate; CPU is a tiebreaker.
	fn score(&self) -> u64 {
		self.active.load(Ordering::Relaxed) as u64 * 1000
			+ self.cpu_util_permille.load(Ordering::Relaxed) as u64
	}
}

struct AffinityEntry {
	socket_idx: AtomicU32, // usize stored as u32 — we'll never have 4B sockets
	last_seen_ns: AtomicU64,
}

struct AffinityMap {
	entries: DashMap<IpAddr, Arc<AffinityEntry>>,
	ttl_ns: u64,
}

pub struct UdsBalancer {
	sockets: Vec<UdsSlot>,
	affinity: Option<AffinityMap>,
}

impl UdsBalancer {
	pub fn new(slots: Vec<UdsSlotSpec>, ip_affinity: bool, affinity_ttl_ms: u64) -> Self {
		let sockets = slots
			.into_iter()
			.map(|s| UdsSlot {
				path: Arc::from(s.path.as_str()),
				active: AtomicU32::new(0),
				health: None,
				pid: s.pid,
				tid: s.tid,
				cpu_util_permille: AtomicU32::new(0),
				last_cpu_ticks: AtomicU64::new(0),
				last_sample_ns: AtomicU64::new(0),
			})
			.collect();

		let affinity = if ip_affinity {
			Some(AffinityMap {
				entries: DashMap::new(),
				ttl_ns: affinity_ttl_ms * 1_000_000,
			})
		} else {
			None
		};

		Self { sockets, affinity }
	}

	/// Track per-slot health for a failover route, reusing `previous`'s state for any path it
	/// shares so a rebuild neither forgets a refusing slot nor detaches in-flight connections from it.
	pub fn with_health(mut self, previous: Option<&UdsBalancer>) -> Self {
		for slot in &mut self.sockets {
			let inherited = previous.and_then(|prev| {
				prev.sockets
					.iter()
					.find(|p| p.path == slot.path)
					.and_then(|p| p.health.clone())
			});
			slot.health = Some(inherited.unwrap_or_default());
		}
		self
	}

	/// Pick a socket for the given peer IP.
	/// If affinity is enabled and the IP has a valid sticky mapping, returns that socket.
	/// Otherwise returns the socket with the lowest combined score (active×1000 + cpu_util).
	/// A refusing slot (failover routes only) is chosen only when every slot is refusing.
	pub fn pick(&self, peer_ip: Option<IpAddr>) -> Option<usize> {
		if self.sockets.is_empty() {
			return None;
		}

		if let (Some(aff), Some(ip)) = (&self.affinity, peer_ip) {
			let now = now_ns();

			// Check existing affinity
			if let Some(entry) = aff.entries.get(&ip) {
				let idx = entry.socket_idx.load(Ordering::Relaxed) as usize;
				let last_seen = entry.last_seen_ns.load(Ordering::Relaxed);
				if idx < self.sockets.len()
					&& now.saturating_sub(last_seen) < aff.ttl_ns
					&& !self.sockets[idx].refusing()
				{
					entry.last_seen_ns.store(now, Ordering::Relaxed);
					return Some(idx);
				}
			}

			// No valid affinity — pick by score and record
			let idx = self.best_score_idx();
			self.bind_affinity(ip, idx, now);
			return Some(idx);
		}

		// No affinity — pick by score
		Some(self.best_score_idx())
	}

	/// The next slot to try after the ones in `tried` failed: best score, refusing slots last.
	pub fn next_untried(&self, tried: &[bool]) -> Option<usize> {
		self.sockets
			.iter()
			.enumerate()
			.filter(|(i, _)| !tried.get(*i).copied().unwrap_or(false))
			.min_by_key(|(_, s)| (s.refusing(), s.score()))
			.map(|(i, _)| i)
	}

	pub fn slot_count(&self) -> usize {
		self.sockets.len()
	}

	pub fn path(&self, idx: usize) -> &Arc<str> {
		&self.sockets[idx].path
	}

	pub fn health(&self, idx: usize) -> Option<&Arc<SlotHealth>> {
		self.sockets[idx].health.as_ref()
	}

	/// Re-point a sticky client at the slot that actually accepted it, so the next connection
	/// from that IP does not start at a slot that just refused.
	pub fn rebind_affinity(&self, peer_ip: Option<IpAddr>, idx: usize) {
		if let (Some(_), Some(ip)) = (&self.affinity, peer_ip) {
			self.bind_affinity(ip, idx, now_ns());
		}
	}

	fn bind_affinity(&self, ip: IpAddr, idx: usize, now: u64) {
		if let Some(aff) = &self.affinity {
			aff.entries.insert(
				ip,
				Arc::new(AffinityEntry {
					socket_idx: AtomicU32::new(idx as u32),
					last_seen_ns: AtomicU64::new(now),
				}),
			);
		}
	}

	/// True when health is tracked and every slot is refusing.
	pub fn all_refusing(&self) -> bool {
		!self.sockets.is_empty()
			&& self
				.sockets
				.iter()
				.all(|s| s.health.as_ref().is_some_and(|h| h.refusing()))
	}

	/// Health-tracked slots: `(path, health)`.
	pub fn tracked_slots(&self) -> impl Iterator<Item = (&Arc<str>, &Arc<SlotHealth>)> {
		self.sockets
			.iter()
			.filter_map(|s| s.health.as_ref().map(|h| (&s.path, h)))
	}

	/// Increment the active counter for a socket path.
	pub fn increment(&self, path: &str) {
		for slot in &self.sockets {
			if slot.path.as_ref() == path {
				slot.active.fetch_add(1, Ordering::Relaxed);
				return;
			}
		}
	}

	/// Decrement the active counter for a socket path.
	pub fn decrement(&self, path: &str) {
		for slot in &self.sockets {
			if slot.path.as_ref() == path {
				slot.active
					.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
						Some(v.saturating_sub(1))
					})
					.ok();
				return;
			}
		}
	}

	pub fn has_affinity(&self) -> bool {
		self.affinity.is_some()
	}

	/// Evict affinity entries older than TTL — the ones `pick()` would no longer honour.
	/// Called by `router::evict_affinity_periodically`.
	pub fn evict_affinity(&self) {
		let Some(aff) = &self.affinity else { return };
		let now = now_ns();
		aff.entries.retain(|_, entry| {
			let last_seen = entry.last_seen_ns.load(Ordering::Relaxed);
			now.saturating_sub(last_seen) < aff.ttl_ns
		});
	}

	#[cfg(test)]
	pub(crate) fn affinity_len(&self) -> usize {
		self.affinity.as_ref().map_or(0, |aff| aff.entries.len())
	}

	/// Returns true if any slot has a pid/tid configured for CPU monitoring.
	pub fn has_monitored_slots(&self) -> bool {
		self.sockets.iter().any(|s| s.pid.is_some())
	}

	/// Read `/proc/{pid}/task/{tid}/stat` for each configured slot and update
	/// `cpu_util_permille`. Called periodically by the background monitor task.
	/// Slots without pid/tid, or where the read fails, are left unchanged (0).
	pub fn update_cpu_stats(&self) {
		let now_ns = now_ns();
		let clk_tck = clk_tck_hz() as f64;

		for slot in &self.sockets {
			let (Some(pid), Some(tid)) = (slot.pid, slot.tid) else {
				continue;
			};
			let Some(ticks) = read_thread_cpu_ticks(pid, tid) else {
				continue;
			};

			let last_ticks = slot.last_cpu_ticks.load(Ordering::Relaxed);
			let last_ns = slot.last_sample_ns.load(Ordering::Relaxed);

			if last_ns > 0 {
				let delta_ticks = ticks.saturating_sub(last_ticks) as f64;
				let delta_secs = now_ns.saturating_sub(last_ns) as f64 / 1_000_000_000.0;
				// util_fraction = delta_ticks / (delta_secs * clk_tck)
				// util_permille = util_fraction * 1000, capped at 1000 (= 100 %)
				let util = if delta_secs > 0.0 {
					(delta_ticks / (delta_secs * clk_tck) * 1000.0).min(1000.0) as u32
				} else {
					0
				};
				slot.cpu_util_permille.store(util, Ordering::Relaxed);
			}

			slot.last_cpu_ticks.store(ticks, Ordering::Relaxed);
			slot.last_sample_ns.store(now_ns, Ordering::Relaxed);
		}
	}

	fn best_score_idx(&self) -> usize {
		self.sockets
			.iter()
			.enumerate()
			.min_by_key(|(_, s)| (s.refusing(), s.score()))
			.map(|(i, _)| i)
			.unwrap_or(0)
	}
}

/// RAII guard that decrements the balancer's active count on drop.
pub struct BalancerGuard {
	balancer: Arc<UdsBalancer>,
	path: String,
}

impl BalancerGuard {
	pub fn new(balancer: Arc<UdsBalancer>, path: String) -> Self {
		balancer.increment(&path);
		Self { balancer, path }
	}
}

impl Drop for BalancerGuard {
	fn drop(&mut self) {
		self.balancer.decrement(&self.path);
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn evict_affinity_drops_only_entries_past_their_ttl() {
		let balancer = UdsBalancer::new(
			vec![UdsSlotSpec {
				path: "/tmp/symphony-test.sock".to_string(),
				pid: None,
				tid: None,
			}],
			true,
			60_000,
		);
		let stale: IpAddr = "192.0.2.1".parse().unwrap();
		let fresh: IpAddr = "192.0.2.2".parse().unwrap();
		balancer.pick(Some(stale));
		balancer.pick(Some(fresh));
		let aff = balancer.affinity.as_ref().unwrap();
		aff.entries
			.get(&stale)
			.unwrap()
			.last_seen_ns
			.store(0, Ordering::Relaxed);

		balancer.evict_affinity();

		assert!(!aff.entries.contains_key(&stale));
		assert!(aff.entries.contains_key(&fresh));
	}
}
