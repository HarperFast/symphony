use crate::thread_cpu::{LoadEwma, ThreadCpu};
use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_ns() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or(Duration::ZERO)
		.as_nanos() as u64
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
	/// `Some` when the slot names its worker thread (`pid` and `tid`). `None` → CPU score 0, pure
	/// least-connections.
	cpu: Option<Arc<ThreadCpu>>,
}

impl UdsSlot {
	fn refusing(&self) -> bool {
		self.health.as_ref().is_some_and(|h| h.refusing())
	}

	/// Combined selection score: active connections dominate; CPU is a tiebreaker.
	fn score(&self) -> u64 {
		self.active.load(Ordering::Relaxed) as u64 * 1000
			+ self.cpu.as_ref().map_or(0, |c| c.util_permille() as u64)
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
	/// Smoothed load of the slots' worker threads, for peer spill-over.
	load: Arc<LoadEwma>,
}

impl UdsBalancer {
	pub fn new(slots: Vec<UdsSlotSpec>, ip_affinity: bool, affinity_ttl_ms: u64) -> Self {
		let sockets = slots
			.into_iter()
			.map(|s| {
				let path: Arc<str> = Arc::from(s.path.as_str());
				let cpu = match (s.pid, s.tid) {
					(Some(pid), Some(tid)) => {
						Some(Arc::new(ThreadCpu::new(path.clone(), pid, tid)))
					}
					_ => None,
				};
				UdsSlot {
					path,
					active: AtomicU32::new(0),
					health: None,
					cpu,
				}
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

		Self {
			sockets,
			affinity,
			load: Arc::default(),
		}
	}

	/// Continue `previous`'s CPU sampling for each slot whose path and configured ids it shares, and
	/// its smoothed load when every slot matches, so a rebuild neither repeats discovery nor
	/// restarts the load from nothing.
	pub fn with_cpu_from(mut self, previous: Option<&UdsBalancer>) -> Self {
		let Some(previous) = previous else {
			return self;
		};
		let mut all_match = self.sockets.len() == previous.sockets.len();
		for slot in &mut self.sockets {
			let Some(cpu) = &slot.cpu else {
				all_match &= previous
					.sockets
					.iter()
					.any(|p| p.path == slot.path && p.cpu.is_none());
				continue;
			};
			let inherited = previous
				.sockets
				.iter()
				.filter_map(|p| p.cpu.as_ref())
				.find(|p| p.configured() == cpu.configured())
				.cloned();
			all_match &= inherited.is_some();
			if let Some(inherited) = inherited {
				slot.cpu = Some(inherited);
			}
		}
		if all_match {
			self.load = previous.load.clone();
		}
		self
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

	/// The same slots and settings with health tracked or not; tracked state stays shared with
	/// `self`. Connection counts and affinity entries start over, as on any rebuild.
	pub fn retracked(&self, track: bool) -> UdsBalancer {
		let slots = self
			.sockets
			.iter()
			.map(|s| UdsSlotSpec {
				path: s.path.to_string(),
				pid: s.cpu.as_ref().map(|c| c.configured().1),
				tid: s.cpu.as_ref().map(|c| c.configured().2),
			})
			.collect();
		let (ip_affinity, ttl_ms) = self
			.affinity
			.as_ref()
			.map_or((false, 0), |a| (true, a.ttl_ns / 1_000_000));
		let balancer = UdsBalancer::new(slots, ip_affinity, ttl_ms).with_cpu_from(Some(self));
		if track {
			balancer.with_health(Some(self))
		} else {
			balancer
		}
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

	pub fn all_refusing(&self) -> bool {
		!self.sockets.is_empty()
			&& self
				.sockets
				.iter()
				.all(|s| s.health.as_ref().is_some_and(|h| h.refusing()))
	}

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
		self.sockets.iter().any(|s| s.cpu.is_some())
	}

	pub fn thread_cpus(&self) -> impl Iterator<Item = &Arc<ThreadCpu>> {
		self.sockets.iter().filter_map(|s| s.cpu.as_ref())
	}

	pub fn load(&self) -> &LoadEwma {
		&self.load
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

	fn monitored(slots: &[(&str, u32, u32)]) -> UdsBalancer {
		UdsBalancer::new(
			slots
				.iter()
				.map(|(path, pid, tid)| UdsSlotSpec {
					path: path.to_string(),
					pid: Some(*pid),
					tid: Some(*tid),
				})
				.collect(),
			false,
			0,
		)
	}

	#[test]
	fn a_rebuild_continues_cpu_sampling_for_unchanged_slots() {
		let old = monitored(&[("/a.sock", 1, 10), ("/b.sock", 1, 11)]);
		let cpus = |b: &UdsBalancer| b.thread_cpus().cloned().collect::<Vec<_>>();

		let same = monitored(&[("/a.sock", 1, 10), ("/b.sock", 1, 11)]).with_cpu_from(Some(&old));
		assert!(cpus(&same)
			.iter()
			.zip(cpus(&old))
			.all(|(a, b)| Arc::ptr_eq(a, &b)));
		assert!(Arc::ptr_eq(&same.load, &old.load));

		let restarted =
			monitored(&[("/a.sock", 1, 10), ("/b.sock", 1, 12)]).with_cpu_from(Some(&old));
		assert!(Arc::ptr_eq(&cpus(&restarted)[0], &cpus(&old)[0]));
		assert!(
			!Arc::ptr_eq(&cpus(&restarted)[1], &cpus(&old)[1]),
			"a new tid is a new thread"
		);
		assert!(
			!Arc::ptr_eq(&restarted.load, &old.load),
			"a changed slot set starts its load over"
		);

		let retracked = old.retracked(true);
		assert!(Arc::ptr_eq(&retracked.load, &old.load));
		assert!(Arc::ptr_eq(&cpus(&retracked)[1], &cpus(&old)[1]));
	}

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
