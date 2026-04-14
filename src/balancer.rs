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

struct UdsSlot {
	path: Arc<str>,
	active: AtomicU32,
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
	pub fn new(paths: Vec<String>, ip_affinity: bool, affinity_ttl_ms: u64) -> Self {
		let sockets = paths
			.into_iter()
			.map(|p| UdsSlot {
				path: Arc::from(p.as_str()),
				active: AtomicU32::new(0),
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

	/// Pick a socket path for the given peer IP.
	/// If affinity is enabled and the IP has a valid sticky mapping, returns that socket.
	/// Otherwise returns the socket with the fewest active connections.
	pub fn pick(&self, peer_ip: Option<IpAddr>) -> Option<Arc<str>> {
		if self.sockets.is_empty() {
			return None;
		}

		if let (Some(aff), Some(ip)) = (&self.affinity, peer_ip) {
			let now = now_ns();

			// Check existing affinity
			if let Some(entry) = aff.entries.get(&ip) {
				let idx = entry.socket_idx.load(Ordering::Relaxed) as usize;
				let last_seen = entry.last_seen_ns.load(Ordering::Relaxed);
				if idx < self.sockets.len() && now.saturating_sub(last_seen) < aff.ttl_ns {
					entry.last_seen_ns.store(now, Ordering::Relaxed);
					return Some(self.sockets[idx].path.clone());
				}
			}

			// No valid affinity — pick by least connections and record
			let idx = self.least_connections_idx();
			let entry = Arc::new(AffinityEntry {
				socket_idx: AtomicU32::new(idx as u32),
				last_seen_ns: AtomicU64::new(now),
			});
			aff.entries.insert(ip, entry);
			return Some(self.sockets[idx].path.clone());
		}

		// No affinity — plain least-connections
		Some(self.sockets[self.least_connections_idx()].path.clone())
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
				// Guard against underflow on unexpected double-decrement
				slot.active.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1))).ok();
				return;
			}
		}
	}

	/// Current active connection count per socket path, for metrics.
	pub fn connection_counts(&self) -> Vec<(String, u32)> {
		self.sockets
			.iter()
			.map(|s| (s.path.to_string(), s.active.load(Ordering::Relaxed)))
			.collect()
	}

	/// Evict affinity entries older than TTL with no active connections.
	/// Called by the background eviction task.
	pub fn evict_affinity(&self) {
		let Some(aff) = &self.affinity else { return };
		let now = now_ns();
		aff.entries.retain(|_, entry| {
			let last_seen = entry.last_seen_ns.load(Ordering::Relaxed);
			now.saturating_sub(last_seen) < aff.ttl_ns
		});
	}

	fn least_connections_idx(&self) -> usize {
		self.sockets
			.iter()
			.enumerate()
			.min_by_key(|(_, s)| s.active.load(Ordering::Relaxed))
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
