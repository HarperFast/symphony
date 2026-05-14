use crate::sni::PeekInfo;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use ipnetwork::IpNetwork;
use std::collections::HashSet;
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

// ── Configuration ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
pub struct ProtectionConfig {
	/// Token bucket: max new connections/second per IP
	pub rate_limit_cps: Option<f64>,
	/// Token bucket burst (defaults to rate_limit_cps if not set)
	pub rate_limit_burst: Option<f64>,
	/// Max simultaneous connections per IP (0 = unlimited)
	pub max_concurrent_per_ip: u32,
	/// JA3 fingerprints to block (raw 16-byte MD5)
	pub ja3_blocklist: HashSet<[u8; 16]>,
	/// Max ms for TLS handshake (0 = use default 10000)
	pub tls_handshake_timeout_ms: u64,
	/// Reject connections without SNI
	pub require_sni: bool,
}

impl ProtectionConfig {
	pub fn tls_handshake_timeout(&self) -> Duration {
		let ms = if self.tls_handshake_timeout_ms == 0 {
			10_000
		} else {
			self.tls_handshake_timeout_ms
		};
		Duration::from_millis(ms)
	}

	/// Token refill rate (tokens per nanosecond), or None if no rate limit.
	pub fn tokens_per_ns(&self) -> Option<f64> {
		self.rate_limit_cps.map(|cps| cps / 1_000_000_000.0)
	}

	/// Burst ceiling in fixed-point (×1000).
	pub fn burst_fp(&self) -> u32 {
		let burst = self
			.rate_limit_burst
			.or(self.rate_limit_cps)
			.unwrap_or(0.0);
		(burst * 1000.0) as u32
	}
}

// ── Per-IP state ──────────────────────────────────────────────────────────────

struct IpState {
	/// Token count in fixed-point ×1000. Max = burst_fp.
	tokens: AtomicU32,
	last_refill_ns: AtomicU64,
	/// Current active connections from this IP.
	active: AtomicU32,
}

impl IpState {
	fn new(burst_fp: u32) -> Self {
		Self {
			tokens: AtomicU32::new(burst_fp),
			last_refill_ns: AtomicU64::new(now_ns()),
			active: AtomicU32::new(0),
		}
	}
}

// ── Decision ──────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum BlockReason {
	CidrBlocked,
	Ja3Blocked,
	NoSni,
	RateLimited,
	TooManyConnections,
}

impl BlockReason {
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::CidrBlocked => "cidr_blocked",
			Self::Ja3Blocked => "ja3_blocked",
			Self::NoSni => "no_sni",
			Self::RateLimited => "rate_limited",
			Self::TooManyConnections => "too_many_connections",
		}
	}
}

#[derive(Debug)]
pub enum Decision {
	/// Connection allowed and active counter incremented — release() must be called on close.
	Allow,
	/// Connection allowed via allowlist — active counter was NOT incremented; release() is a no-op.
	AllowBypassed,
	Block(BlockReason),
}

// ── ProtectionState ───────────────────────────────────────────────────────────

pub struct ProtectionState {
	pub config: ArcSwap<ProtectionConfig>,
	ip_table: DashMap<IpAddr, Arc<IpState>>,
	allowlist: Vec<IpNetwork>,
	blocklist: Vec<IpNetwork>,
}

impl ProtectionState {
	pub fn new(
		config: ProtectionConfig,
		allowlist: Vec<IpNetwork>,
		blocklist: Vec<IpNetwork>,
	) -> Arc<Self> {
		Arc::new(Self {
			config: ArcSwap::new(Arc::new(config)),
			ip_table: DashMap::new(),
			allowlist,
			blocklist,
		})
	}

	/// Check whether to allow or block a new connection.
	/// If allowed, increments the IP's active counter.
	pub fn check(&self, peer_ip: IpAddr, peek_info: &PeekInfo) -> Decision {
		let cfg = self.config.load();

		// 1. Allowlist — skip all other checks; active counter is NOT incremented
		for network in &self.allowlist {
			if network.contains(peer_ip) {
				return Decision::AllowBypassed;
			}
		}

		// 2. Blocklist
		for network in &self.blocklist {
			if network.contains(peer_ip) {
				return Decision::Block(BlockReason::CidrBlocked);
			}
		}

		// 3. JA3 blocklist
		if !cfg.ja3_blocklist.is_empty() && peek_info.ja3.len() == 32 {
			if let Some(bytes) = hex_to_bytes16(&peek_info.ja3) {
				if cfg.ja3_blocklist.contains(&bytes) {
					return Decision::Block(BlockReason::Ja3Blocked);
				}
			}
		}

		// 4. Require SNI
		if cfg.require_sni && peek_info.sni.is_none() {
			return Decision::Block(BlockReason::NoSni);
		}

		// 5 & 6: Rate limit + concurrency — access IpState once
		let state = self.get_or_create_state(peer_ip, cfg.burst_fp());

		// 5. Token bucket rate limit
		if let Some(rate) = cfg.tokens_per_ns() {
			let now = now_ns();
			let burst_fp = cfg.burst_fp();

			// Refill tokens
			loop {
				let last = state.last_refill_ns.load(Ordering::Relaxed);
				let elapsed = now.saturating_sub(last);
				let refill = ((elapsed as f64) * rate * 1000.0) as u32;
				if refill == 0 {
					break;
				}
				let old_tokens = state.tokens.load(Ordering::Relaxed);
				let new_tokens = old_tokens.saturating_add(refill).min(burst_fp);
				// CAS: update tokens and last_refill atomically
				if state
					.tokens
					.compare_exchange(old_tokens, new_tokens, Ordering::Relaxed, Ordering::Relaxed)
					.is_ok()
				{
					// CAS on the timestamp so only the first winner advances the refill window.
					// A losing compare_exchange here is harmless — another thread already wrote it.
					let _ = state.last_refill_ns.compare_exchange(
						last, now, Ordering::Relaxed, Ordering::Relaxed,
					);
					break;
				}
				// CAS failed — another thread beat us; retry
			}

			// Try to consume 1 token (= 1000 fixed-point units)
			const ONE_TOKEN: u32 = 1000;
			loop {
				let tokens = state.tokens.load(Ordering::Relaxed);
				if tokens < ONE_TOKEN {
					return Decision::Block(BlockReason::RateLimited);
				}
				if state
					.tokens
					.compare_exchange(tokens, tokens - ONE_TOKEN, Ordering::Relaxed, Ordering::Relaxed)
					.is_ok()
				{
					break;
				}
			}
		}

		// 6. Concurrency limit — atomic test-and-increment to avoid TOCTOU
		if cfg.max_concurrent_per_ip > 0 {
			let max = cfg.max_concurrent_per_ip;
			let result = state.active.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
				if v < max { Some(v + 1) } else { None }
			});
			if result.is_err() {
				return Decision::Block(BlockReason::TooManyConnections);
			}
			// fetch_update already incremented the counter
		} else {
			state.active.fetch_add(1, Ordering::Relaxed);
		}
		Decision::Allow
	}

	/// Decrement the active counter for a peer IP. Call on connection close.
	pub fn release(&self, peer_ip: IpAddr) {
		if let Some(state) = self.ip_table.get(&peer_ip) {
			state
				.active
				.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)))
				.ok();
		}
	}

	/// Returns (rate_limited_ips, concurrency_limited_ips) for the `blockedIps()` API.
	pub fn blocked_ips(&self, max_concurrent: u32) -> (Vec<IpAddr>, Vec<IpAddr>) {
		let cfg = self.config.load();
		let burst_fp = cfg.burst_fp();
		let mut rate_limited = Vec::new();
		let mut concurrency_limited = Vec::new();

		for entry in self.ip_table.iter() {
			let ip = *entry.key();
			let state = entry.value();

			if cfg.tokens_per_ns().is_some() && state.tokens.load(Ordering::Relaxed) < 1000 {
				rate_limited.push(ip);
			}
			if max_concurrent > 0 {
				let active = state.active.load(Ordering::Relaxed);
				// Track IPs that are AT the limit (>= max) — they'd be blocked
				if active >= max_concurrent && burst_fp > 0 {
					concurrency_limited.push(ip);
				}
			}
		}

		(rate_limited, concurrency_limited)
	}

	/// Evict idle, fully-refilled IpState entries to bound memory.
	/// Called by the background eviction task every 60 seconds.
	pub fn evict(&self) {
		let cfg = self.config.load();
		let burst_fp = cfg.burst_fp();
		self.ip_table.retain(|_, state| {
			// Keep entry if: there are active connections, OR the bucket is not full
			state.active.load(Ordering::Relaxed) > 0
				|| (burst_fp > 0 && state.tokens.load(Ordering::Relaxed) < burst_fp)
		});
	}

	fn get_or_create_state(&self, ip: IpAddr, burst_fp: u32) -> Arc<IpState> {
		if let Some(s) = self.ip_table.get(&ip) {
			return s.clone();
		}
		let state = Arc::new(IpState::new(burst_fp));
		self.ip_table.entry(ip).or_insert_with(|| state).clone()
	}
}

fn hex_to_bytes16(hex: &str) -> Option<[u8; 16]> {
	if hex.len() != 32 {
		return None;
	}
	let mut out = [0u8; 16];
	for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
		let hi = from_hex_digit(chunk[0])?;
		let lo = from_hex_digit(chunk[1])?;
		out[i] = (hi << 4) | lo;
	}
	Some(out)
}

fn from_hex_digit(b: u8) -> Option<u8> {
	match b {
		b'0'..=b'9' => Some(b - b'0'),
		b'a'..=b'f' => Some(b - b'a' + 10),
		b'A'..=b'F' => Some(b - b'A' + 10),
		_ => None,
	}
}
