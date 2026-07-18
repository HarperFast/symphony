use crate::sni::PeekInfo;
use arc_swap::ArcSwap;
use dashmap::DashMap;
use ipnetwork::IpNetwork;
use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

// Process-wide monotonic anchor. All timing uses monotonic offsets from process start.
// Trade-off vs wall-clock: deadlines and bucket timestamps cannot be compared to unix time,
// but forward NTP steps no longer release penalty-boxed IPs early and backward steps no
// longer freeze legitimate bucket refills. Values are only compared internally.
static START: OnceLock<Instant> = OnceLock::new();

fn now_ns() -> u64 {
	Instant::now()
		.duration_since(*START.get_or_init(Instant::now))
		.as_nanos() as u64
}

// ── Configuration ─────────────────────────────────────────────────────────────

/// Snapshot of all protection settings for a listener.
/// Stored inside ArcSwap so every field is hot-swappable in one atomic pointer store.
#[derive(Clone, Debug, Default)]
pub struct ProtectionConfig {
	/// Per-second token bucket: max new connections/second per IP.
	pub rate_limit_cps: Option<f64>,
	/// Per-second burst ceiling (defaults to rate_limit_cps if not set).
	pub rate_limit_burst: Option<f64>,
	/// Sustained token bucket: max new connections/minute per IP.
	/// Independent of the per-second bucket; either exhausting → block.
	pub sustained_cpm: Option<f64>,
	/// Sustained burst ceiling (defaults to sustained_cpm if not set).
	/// Max useful value: 4,294,967 connections (u32::MAX / 1000 fixed-point units).
	pub sustained_burst: Option<f64>,
	/// Penalty box duration in ms. 0 = penalty box disabled (default).
	/// When > 0: exhausting any rate limit places the IP in the penalty box for this duration.
	/// While boxed, all connections are blocked. If the IP continues to hit rate limits while
	/// boxed, the penalty is extended (reset to full duration from now).
	pub penalty_box_duration_ms: u64,
	/// Max simultaneous connections per IP (0 = unlimited).
	pub max_concurrent_per_ip: u32,
	/// JA3 fingerprints to block (raw 16-byte MD5).
	pub ja3_blocklist: HashSet<[u8; 16]>,
	/// JA4 fingerprints to block. Values are stored lowercase; comparison is case-insensitive.
	/// JA4 strings are 36-char lowercase ASCII: t<ver><sni><cc><ec><alpn>_<12hex>_<12hex>.
	pub ja4_blocklist: HashSet<Box<str>>,
	/// Max ms for TLS handshake (0 = use default 10000).
	pub tls_handshake_timeout_ms: u64,
	/// Reject connections without SNI.
	pub require_sni: bool,
	/// CIDRs that bypass all protection checks.
	pub allowlist: Vec<IpNetwork>,
	/// CIDRs that are always blocked.
	pub blocklist: Vec<IpNetwork>,

	// Precomputed derived constants — populated by ProtectionConfig::precompute().
	// These replace the method-based lookups on the hot check() path.
	/// Per-second token refill rate (tokens per nanosecond). 0.0 = no limit.
	pub tokens_per_ns: f64,
	/// Per-second burst ceiling in fixed-point (×1000). 0 = no limit.
	pub burst_fp: u32,
	/// Sustained token refill rate (tokens per nanosecond). 0.0 = no limit.
	pub sustained_tokens_per_ns: f64,
	/// Sustained burst ceiling in fixed-point (×1000). 0 = no limit.
	pub sustained_burst_fp: u32,
}

impl ProtectionConfig {
	/// Compute and cache float-derived constants from the source fields.
	/// Must be called after setting all rate-limit fields, before ArcSwap storage.
	pub fn precompute(mut self) -> Self {
		self.burst_fp = (self.rate_limit_burst.or(self.rate_limit_cps).unwrap_or(0.0) * 1000.0) as u32;
		self.tokens_per_ns = self.rate_limit_cps.map_or(0.0, |cps| cps / 1_000_000_000.0);
		self.sustained_burst_fp =
			(self.sustained_burst.or(self.sustained_cpm).unwrap_or(0.0) * 1000.0) as u32;
		// 1 minute = 60_000_000_000 ns
		self.sustained_tokens_per_ns = self.sustained_cpm.map_or(0.0, |cpm| cpm / 60_000_000_000.0);
		self
	}

	pub fn tls_handshake_timeout(&self) -> Duration {
		let ms = if self.tls_handshake_timeout_ms == 0 { 10_000 } else { self.tls_handshake_timeout_ms };
		Duration::from_millis(ms)
	}
}

// ── Per-IP state ──────────────────────────────────────────────────────────────

#[derive(Debug)]
pub(crate) struct IpState {
	/// Per-second token count in fixed-point ×1000. Max = burst_fp.
	tokens: AtomicU32,
	last_refill_ns: AtomicU64,
	/// Sustained (per-minute) token count in fixed-point ×1000. Max = sustained_burst_fp.
	sustained_tokens: AtomicU32,
	sustained_last_refill_ns: AtomicU64,
	/// Current active connections from this IP.
	pub(crate) active: AtomicU32,
	/// Penalty box deadline in monotonic ns (relative to START). 0 = not penalized.
	penalty_deadline_ns: AtomicU64,
}

impl IpState {
	fn new(burst_fp: u32, sustained_burst_fp: u32) -> Self {
		let now = now_ns();
		Self {
			tokens: AtomicU32::new(burst_fp),
			last_refill_ns: AtomicU64::new(now),
			sustained_tokens: AtomicU32::new(sustained_burst_fp),
			sustained_last_refill_ns: AtomicU64::new(now),
			active: AtomicU32::new(0),
			penalty_deadline_ns: AtomicU64::new(0),
		}
	}

	/// Decrement the active counter. Called via the held Arc on connection close.
	pub(crate) fn release(&self) {
		self.active
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)))
			.ok();
	}
}

// ── Token bucket helpers ───────────────────────────────────────────────────────

/// Refills a token bucket from elapsed time, then tries to consume one token (1000 fp units).
/// Returns true if a token was consumed (connection allowed), false if bucket was empty.
/// Lock-free: uses Relaxed CAS retry loops.
fn refill_and_consume(
	tokens: &AtomicU32,
	last_refill_ns: &AtomicU64,
	now: u64,
	rate_per_ns: f64,
	burst_fp: u32,
) -> bool {
	// Refill phase — caps at burst_fp to handle burst decreases without underflow.
	loop {
		let last = last_refill_ns.load(Ordering::Relaxed);
		let elapsed = now.saturating_sub(last);
		let refill = ((elapsed as f64) * rate_per_ns * 1000.0) as u32;
		if refill == 0 {
			break;
		}
		let old_tokens = tokens.load(Ordering::Relaxed);
		let new_tokens = old_tokens.saturating_add(refill).min(burst_fp);
		if tokens
			.compare_exchange(old_tokens, new_tokens, Ordering::Relaxed, Ordering::Relaxed)
			.is_ok()
		{
			// Only the first CAS winner advances the refill timestamp; losers retry from above.
			let _ = last_refill_ns.compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed);
			break;
		}
	}

	// Consume phase — 1 token = 1000 fixed-point units
	const ONE_TOKEN: u32 = 1000;
	loop {
		let t = tokens.load(Ordering::Relaxed);
		if t < ONE_TOKEN {
			return false;
		}
		if tokens
			.compare_exchange(t, t - ONE_TOKEN, Ordering::Relaxed, Ordering::Relaxed)
			.is_ok()
		{
			return true;
		}
	}
}

// ── Decision ──────────────────────────────────────────────────────────────────

#[derive(Debug, PartialEq, Eq)]
pub enum BlockReason {
	CidrBlocked,
	Ja3Blocked,
	Ja4Blocked,
	NoSni,
	RateLimited,
	TooManyConnections,
	/// IP is in the penalty box — placed here by prior rate limit exhaustion.
	PenaltyBoxed,
}

impl BlockReason {
	pub fn as_str(&self) -> &'static str {
		match self {
			Self::CidrBlocked => "cidr_blocked",
			Self::Ja3Blocked => "ja3_blocked",
			Self::Ja4Blocked => "ja4_blocked",
			Self::NoSni => "no_sni",
			Self::RateLimited => "rate_limited",
			Self::TooManyConnections => "too_many_connections",
			Self::PenaltyBoxed => "penalty_boxed",
		}
	}
}

#[derive(Debug)]
pub enum Decision {
	/// Connection allowed and active counter incremented.
	/// The caller MUST hold this Arc until connection close and call ip_state.release() on drop.
	Allow(Arc<IpState>),
	/// Connection allowed via allowlist — active counter was NOT incremented.
	AllowBypassed,
	Block(BlockReason),
}

// ── ProtectionState ───────────────────────────────────────────────────────────

pub struct ProtectionState {
	/// All protection settings in one ArcSwap snapshot — a single store() reaches all checks.
	pub config: ArcSwap<ProtectionConfig>,
	ip_table: DashMap<IpAddr, Arc<IpState>>,
}

impl ProtectionState {
	pub fn new(config: ProtectionConfig) -> Arc<Self> {
		Arc::new(Self {
			config: ArcSwap::new(Arc::new(config.precompute())),
			ip_table: DashMap::new(),
		})
	}

	/// Check whether to allow or block a new connection.
	/// On Allow, increments the IP's active counter and returns the IpState Arc the caller
	/// must hold until connection close (call ip_state.release() on drop).
	pub fn check(&self, peer_ip: IpAddr, peek_info: &PeekInfo) -> Decision {
		self.check_at(peer_ip, peek_info, now_ns())
	}

	/// Internal: same as check() but accepts an explicit `now_ns` timestamp for testing.
	pub(crate) fn check_at(&self, peer_ip: IpAddr, peek_info: &PeekInfo, now: u64) -> Decision {
		let cfg = self.config.load();

		// 1. Allowlist — skip all other checks; active counter is NOT incremented.
		for network in &cfg.allowlist {
			if network.contains(peer_ip) {
				return Decision::AllowBypassed;
			}
		}

		// 2. Blocklist
		for network in &cfg.blocklist {
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

		// 3b. JA4 blocklist
		if !cfg.ja4_blocklist.is_empty()
			&& !peek_info.ja4.is_empty()
			&& cfg.ja4_blocklist.contains(peek_info.ja4.as_str())
		{
			return Decision::Block(BlockReason::Ja4Blocked);
		}

		// 4. Require SNI
		if cfg.require_sni && peek_info.sni.is_none() {
			return Decision::Block(BlockReason::NoSni);
		}

		// 5–8: IP-state checks — access IpState once
		let state = self.get_or_create_state(peer_ip, cfg.burst_fp, cfg.sustained_burst_fp);

		// 5. Penalty box — if the IP is currently penalized, debit buckets to detect continued
		//    excess and extend the deadline if found, then block outright.
		let penalty_ms = cfg.penalty_box_duration_ms;
		if penalty_ms > 0 {
			let deadline = state.penalty_deadline_ns.load(Ordering::Relaxed);
			if deadline > 0 && now < deadline {
				// Debit both rate buckets to measure "continues to exceed".
				// If either bucket is exhausted, the attacker is still hitting hard → extend.
				let mut exceeded = false;
				if cfg.tokens_per_ns > 0.0
					&& !refill_and_consume(
						&state.tokens,
						&state.last_refill_ns,
						now,
						cfg.tokens_per_ns,
						cfg.burst_fp,
					) {
					exceeded = true;
				}
				if cfg.sustained_tokens_per_ns > 0.0
					&& !refill_and_consume(
						&state.sustained_tokens,
						&state.sustained_last_refill_ns,
						now,
						cfg.sustained_tokens_per_ns,
						cfg.sustained_burst_fp,
					) {
					exceeded = true;
				}
				if exceeded {
					// Extend deadline monotonically — fetch_max prevents inter-thread now_ns
					// skew from regressing a deadline set by a concurrent writer.
					state.penalty_deadline_ns.fetch_max(
						now.saturating_add(penalty_ms.saturating_mul(1_000_000)),
						Ordering::Relaxed,
					);
				}
				return Decision::Block(BlockReason::PenaltyBoxed);
			}
		}

		// 6. Per-second rate limit
		if cfg.tokens_per_ns > 0.0
			&& !refill_and_consume(&state.tokens, &state.last_refill_ns, now, cfg.tokens_per_ns, cfg.burst_fp)
		{
			if penalty_ms > 0 {
				state.penalty_deadline_ns.fetch_max(
					now.saturating_add(penalty_ms.saturating_mul(1_000_000)),
					Ordering::Relaxed,
				);
			}
			return Decision::Block(BlockReason::RateLimited);
		}

		// 7. Sustained rate limit (per-minute)
		if cfg.sustained_tokens_per_ns > 0.0
			&& !refill_and_consume(
				&state.sustained_tokens,
				&state.sustained_last_refill_ns,
				now,
				cfg.sustained_tokens_per_ns,
				cfg.sustained_burst_fp,
			)
		{
			if penalty_ms > 0 {
				state.penalty_deadline_ns.fetch_max(
					now.saturating_add(penalty_ms.saturating_mul(1_000_000)),
					Ordering::Relaxed,
				);
			}
			return Decision::Block(BlockReason::RateLimited);
		}

		// 8. Concurrency limit — atomic test-and-increment to avoid TOCTOU
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
		Decision::Allow(state)
	}

	/// Decrement the active counter for a peer IP. Used by tests; production code uses
	/// the Arc<IpState> returned from check() so the decrement hits the same entry even
	/// if an eviction ran between admission and close.
	#[cfg(test)]
	pub fn release(&self, peer_ip: IpAddr) {
		if let Some(state) = self.ip_table.get(&peer_ip) {
			state.release();
		}
	}

	/// Returns (rate_limited_ips, concurrency_limited_ips, penalty_boxed_ips) for the `blockedIps()` API.
	pub fn blocked_ips(&self) -> (Vec<IpAddr>, Vec<IpAddr>, Vec<IpAddr>) {
		let cfg = self.config.load();
		let max_concurrent = cfg.max_concurrent_per_ip;
		let now = now_ns();
		let mut rate_limited = Vec::new();
		let mut concurrency_limited = Vec::new();
		let mut penalty_boxed = Vec::new();

		for entry in self.ip_table.iter() {
			let ip = *entry.key();
			let state = entry.value();

			// Penalty box: only report when the feature is currently enabled in config.
			// After a hot-swap that disables penaltyBox, check() stops enforcing it but
			// stale deadlines remain on IpState until expiry — gate on config to avoid
			// reporting IPs that are no longer actually blocked.
			if cfg.penalty_box_duration_ms > 0 {
				let deadline = state.penalty_deadline_ns.load(Ordering::Relaxed);
				if deadline > 0 && now < deadline {
					penalty_boxed.push(ip);
					continue;
				}
			}

			// Rate-limited: apply lazy projection (same logic as evict_at) so a recovered
			// idle IP isn't falsely reported as still limited.
			let mut is_rate_limited = false;
			if cfg.tokens_per_ns > 0.0 {
				let last = state.last_refill_ns.load(Ordering::Relaxed);
				let current = state.tokens.load(Ordering::Relaxed);
				let refill = ((now.saturating_sub(last) as f64) * cfg.tokens_per_ns * 1000.0) as u32;
				let projected = current.saturating_add(refill).min(cfg.burst_fp);
				if projected < 1000 {
					is_rate_limited = true;
				}
			}
			if !is_rate_limited && cfg.sustained_tokens_per_ns > 0.0 {
				let last = state.sustained_last_refill_ns.load(Ordering::Relaxed);
				let current = state.sustained_tokens.load(Ordering::Relaxed);
				let refill =
					((now.saturating_sub(last) as f64) * cfg.sustained_tokens_per_ns * 1000.0) as u32;
				let projected = current.saturating_add(refill).min(cfg.sustained_burst_fp);
				if projected < 1000 {
					is_rate_limited = true;
				}
			}
			if is_rate_limited {
				rate_limited.push(ip);
			}
			if max_concurrent > 0 {
				let active = state.active.load(Ordering::Relaxed);
				// Track IPs that are AT the limit (>= max) — they'd be blocked on next connect.
				if active >= max_concurrent {
					concurrency_limited.push(ip);
				}
			}
		}

		(rate_limited, concurrency_limited, penalty_boxed)
	}

	/// Returns (rate_limited_ips, concurrency_limited_ips, penalty_boxed_ips) at a given time.
	/// Test seam for fix 5 verification.
	#[cfg(test)]
	pub(crate) fn blocked_ips_at(&self, now: u64) -> (Vec<IpAddr>, Vec<IpAddr>, Vec<IpAddr>) {
		let cfg = self.config.load();
		let max_concurrent = cfg.max_concurrent_per_ip;
		let mut rate_limited = Vec::new();
		let mut concurrency_limited = Vec::new();
		let mut penalty_boxed = Vec::new();

		for entry in self.ip_table.iter() {
			let ip = *entry.key();
			let state = entry.value();

			if cfg.penalty_box_duration_ms > 0 {
				let deadline = state.penalty_deadline_ns.load(Ordering::Relaxed);
				if deadline > 0 && now < deadline {
					penalty_boxed.push(ip);
					continue;
				}
			}

			let mut is_rate_limited = false;
			if cfg.tokens_per_ns > 0.0 {
				let last = state.last_refill_ns.load(Ordering::Relaxed);
				let current = state.tokens.load(Ordering::Relaxed);
				let refill = ((now.saturating_sub(last) as f64) * cfg.tokens_per_ns * 1000.0) as u32;
				if current.saturating_add(refill).min(cfg.burst_fp) < 1000 {
					is_rate_limited = true;
				}
			}
			if !is_rate_limited && cfg.sustained_tokens_per_ns > 0.0 {
				let last = state.sustained_last_refill_ns.load(Ordering::Relaxed);
				let current = state.sustained_tokens.load(Ordering::Relaxed);
				let refill =
					((now.saturating_sub(last) as f64) * cfg.sustained_tokens_per_ns * 1000.0) as u32;
				if current.saturating_add(refill).min(cfg.sustained_burst_fp) < 1000 {
					is_rate_limited = true;
				}
			}
			if is_rate_limited {
				rate_limited.push(ip);
			}
			if max_concurrent > 0 && state.active.load(Ordering::Relaxed) >= max_concurrent {
				concurrency_limited.push(ip);
			}
		}

		(rate_limited, concurrency_limited, penalty_boxed)
	}

	/// Evict idle IpState entries to bound ip_table memory growth.
	/// Called by the background eviction task every 60 seconds.
	pub fn evict(&self) {
		self.evict_at(now_ns());
	}

	/// Internal: same as evict() but accepts an explicit `now_ns` for testing.
	///
	/// Retains an entry if ANY of:
	/// - It is in the penalty box (penalty_deadline_ns > now).
	/// - It has active connections.
	/// - Its per-second bucket would not yet be fully refilled (lazy projection from last_refill_ns).
	/// - Its sustained bucket would not yet be fully refilled (lazy projection).
	///
	/// Lazy projection means an attacker cannot reset their sustained window by pausing
	/// until eviction: the entry stays until the full burst_fp would be recovered.
	pub(crate) fn evict_at(&self, now: u64) {
		let cfg = self.config.load();

		self.ip_table.retain(|_, state| {
			// Keep: in the penalty box — but only when penaltyBox is currently enabled.
			// A stale deadline left from a prior enabled window must not pin the entry
			// after penaltyBox is disabled; otherwise re-enabling resurrects old deadlines.
			let deadline = state.penalty_deadline_ns.load(Ordering::Relaxed);
			if cfg.penalty_box_duration_ms > 0 && deadline > 0 && now < deadline {
				return true;
			}

			// Keep: active connections
			if state.active.load(Ordering::Relaxed) > 0 {
				return true;
			}

			// Keep: per-second bucket would not yet be fully refilled
			if cfg.tokens_per_ns > 0.0 {
				let burst_fp = cfg.burst_fp;
				let last = state.last_refill_ns.load(Ordering::Relaxed);
				let current = state.tokens.load(Ordering::Relaxed);
				let refill = ((now.saturating_sub(last) as f64) * cfg.tokens_per_ns * 1000.0) as u32;
				if current.saturating_add(refill).min(burst_fp) < burst_fp {
					return true;
				}
			}

			// Keep: sustained bucket would not yet be fully refilled
			if cfg.sustained_tokens_per_ns > 0.0 {
				let burst_fp = cfg.sustained_burst_fp;
				let last = state.sustained_last_refill_ns.load(Ordering::Relaxed);
				let current = state.sustained_tokens.load(Ordering::Relaxed);
				let refill =
					((now.saturating_sub(last) as f64) * cfg.sustained_tokens_per_ns * 1000.0) as u32;
				if current.saturating_add(refill).min(burst_fp) < burst_fp {
					return true;
				}
			}

			false // evict: idle, not penalized, both buckets would be fully refilled
		});
	}

	fn get_or_create_state(&self, ip: IpAddr, burst_fp: u32, sustained_burst_fp: u32) -> Arc<IpState> {
		if let Some(s) = self.ip_table.get(&ip) {
			return s.clone();
		}
		let state = Arc::new(IpState::new(burst_fp, sustained_burst_fp));
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::sni::PeekInfo;

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

	fn no_peek() -> PeekInfo {
		PeekInfo::default()
	}

	fn peek_with_ja3(hex: &str) -> PeekInfo {
		PeekInfo { ja3: hex.to_string(), ..Default::default() }
	}

	#[test]
	fn cidr_block_hot_swap_adds_block() {
		let state = ProtectionState::new(ProtectionConfig::default());
		let peer = ip("10.0.0.1");

		// Initially allowed
		assert!(matches!(state.check(peer, &no_peek()), Decision::Allow(_)));
		state.release(peer);

		// Swap in a blocklist containing the peer
		state.config.store(Arc::new(
			ProtectionConfig {
				blocklist: vec!["10.0.0.0/24".parse().unwrap()],
				..Default::default()
			}
			.precompute(),
		));
		assert!(matches!(state.check(peer, &no_peek()), Decision::Block(BlockReason::CidrBlocked)));
	}

	#[test]
	fn cidr_block_hot_swap_removes_block() {
		let state = ProtectionState::new(ProtectionConfig {
			blocklist: vec!["10.0.0.0/8".parse().unwrap()],
			..Default::default()
		});
		let peer = ip("10.1.2.3");

		assert!(matches!(state.check(peer, &no_peek()), Decision::Block(BlockReason::CidrBlocked)));

		// Remove the blocklist
		state.config.store(Arc::new(ProtectionConfig::default().precompute()));
		assert!(matches!(state.check(peer, &no_peek()), Decision::Allow(_)));
		state.release(peer);
	}

	#[test]
	fn allowlist_bypass_overrides_blocklist() {
		let state = ProtectionState::new(ProtectionConfig {
			blocklist: vec!["10.0.0.0/8".parse().unwrap()],
			..Default::default()
		});
		let peer = ip("10.0.0.5");

		// Initially blocked by CIDR
		assert!(matches!(state.check(peer, &no_peek()), Decision::Block(BlockReason::CidrBlocked)));

		// Add an allowlist covering that IP — allowlist check runs before blocklist
		state.config.store(Arc::new(
			ProtectionConfig {
				allowlist: vec!["10.0.0.0/24".parse().unwrap()],
				blocklist: vec!["10.0.0.0/8".parse().unwrap()],
				..Default::default()
			}
			.precompute(),
		));
		assert!(matches!(state.check(peer, &no_peek()), Decision::AllowBypassed));
	}

	#[test]
	fn ja3_block_hot_swap() {
		let state = ProtectionState::new(ProtectionConfig::default());
		let peer = ip("1.2.3.4");
		let hex = "e7d705a3286e19ea42f587b344ee6865";

		assert!(matches!(state.check(peer, &peek_with_ja3(hex)), Decision::Allow(_)));
		state.release(peer);

		// Swap in a JA3 blocklist
		let mut new_cfg = ProtectionConfig::default();
		new_cfg.ja3_blocklist.insert(hex_to_bytes16(hex).unwrap());
		state.config.store(Arc::new(new_cfg.precompute()));
		assert!(matches!(state.check(peer, &peek_with_ja3(hex)), Decision::Block(BlockReason::Ja3Blocked)));
	}

	#[test]
	fn rate_limit_hot_swap_enables_limiting() {
		// Start with no rate limit — ip_table entry created with burst_fp=0 (tokens=0)
		let state = ProtectionState::new(ProtectionConfig::default());
		let peer = ip("2.0.0.1");

		assert!(matches!(state.check(peer, &no_peek()), Decision::Allow(_)));
		state.release(peer);

		// Enable rate limiting with burst < ONE_TOKEN (1000 fp), so the existing entry
		// (tokens=0) will never accumulate enough to pass the consume step.
		// burst_fp = (0.5 * 1000.0) as u32 = 500 < 1000 = ONE_TOKEN → always blocked.
		state.config.store(Arc::new(
			ProtectionConfig {
				rate_limit_cps: Some(10.0),
				rate_limit_burst: Some(0.5),
				..Default::default()
			}
			.precompute(),
		));
		assert!(matches!(state.check(peer, &no_peek()), Decision::Block(BlockReason::RateLimited)));
	}

	#[test]
	fn rate_limit_hot_swap_loosens_limit() {
		// Start with a very tight rate limit — burst_fp=1 so immediately rate-limited
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(1.0),
			rate_limit_burst: Some(0.001), // burst_fp=1, ONE_TOKEN=1000 → always blocked
			..Default::default()
		});
		let peer = ip("2.0.0.2");

		assert!(matches!(state.check(peer, &no_peek()), Decision::Block(BlockReason::RateLimited)));

		// Remove rate limit entirely — now unrestricted
		state.config.store(Arc::new(ProtectionConfig::default().precompute()));
		assert!(matches!(state.check(peer, &no_peek()), Decision::Allow(_)));
		state.release(peer);
	}

	#[test]
	fn burst_decrease_no_underflow() {
		// Start with a generous burst (100 tokens = 100000 fp)
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(100.0),
			rate_limit_burst: Some(100.0),
			..Default::default()
		});
		let peer = ip("3.0.0.1");

		// Consume 50 tokens — each check decrements by 1000 fp; 50 × 1000 = 50000 fp consumed
		for _ in 0..50 {
			assert!(matches!(state.check(peer, &no_peek()), Decision::Allow(_)));
			state.release(peer);
		}
		// tokens ≈ 50000 fp (remaining in bucket; negligible refill during fast loop)

		// Reduce burst to 1 (burst_fp=1000). On next refill the bucket will be capped.
		// Existing tokens (50000) remain until first refill; no underflow in consume step.
		state.config.store(Arc::new(
			ProtectionConfig {
				rate_limit_cps: Some(1.0),
				rate_limit_burst: Some(1.0),
				..Default::default()
			}
			.precompute(),
		));

		// Consume step: tokens ≈ 50000 fp → 50000 - 1000 = 49000 fp; no underflow
		assert!(matches!(state.check(peer, &no_peek()), Decision::Allow(_)));
		state.release(peer);
	}

	#[test]
	fn blocked_ips_reports_concurrency_limited_without_rate_limit() {
		// Concurrency cap with NO rate limit — burst_fp is 0, but concurrency-limited IPs
		// must still appear in blocked_ips(). The old `&& burst_fp > 0` guard was wrong.
		let state = ProtectionState::new(ProtectionConfig {
			max_concurrent_per_ip: 1,
			..Default::default()
		});
		let peer = ip("5.0.0.1");

		// First connection: allowed and active counter incremented (not released yet).
		assert!(matches!(state.check(peer, &no_peek()), Decision::Allow(_)));

		// IP is now at the concurrency limit; blocked_ips() must report it.
		let (rl, cl, _) = state.blocked_ips();
		assert!(rl.is_empty(), "no rate limit configured — rateLimited must be empty");
		assert!(cl.contains(&peer), "IP at concurrency limit must appear in concurrencyLimited");

		state.release(peer);
	}

	// ── Sustained rate limit tests ─────────────────────────────────────────────

	#[test]
	fn sustained_bucket_enforced_independently() {
		// High per-second rate (100 cps) but low sustained burst (3 connections total).
		// After 3 connections the sustained bucket is exhausted; the 4th is blocked
		// despite the per-second bucket still having tokens.
		let now = now_ns();
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(100.0),
			rate_limit_burst: Some(100.0),
			sustained_cpm: Some(60.0), // 1 per second in sustained terms
			sustained_burst: Some(3.0),
			..Default::default()
		});
		let peer = ip("4.0.0.1");

		// All at the same timestamp so no refill occurs between calls.
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Allow(_)));
		state.release(peer);
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Allow(_)));
		state.release(peer);
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Allow(_)));
		state.release(peer);

		// Sustained burst exhausted — 4th is blocked
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::RateLimited)));
	}

	#[test]
	fn sustained_bucket_refills_over_time() {
		// 60 CPM = 1 per second. Sustained burst = 1. After exhausting, 1 second of wait
		// refills exactly 1 token, allowing the next connection.
		let now = now_ns();
		let state = ProtectionState::new(ProtectionConfig {
			sustained_cpm: Some(60.0),
			sustained_burst: Some(1.0),
			..Default::default()
		});
		let peer = ip("4.0.0.2");

		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Allow(_)));
		state.release(peer);
		// Sustained bucket exhausted
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::RateLimited)));

		// 1.1 seconds later — bucket refilled by 1.1 tokens, capped at burst 1 → allows
		let later = now + 1_100_000_000; // 1.1 s in ns
		assert!(matches!(state.check_at(peer, &no_peek(), later), Decision::Allow(_)));
		state.release(peer);
	}

	#[test]
	fn sustained_does_not_block_without_sustained_config() {
		// Only per-second limit configured — sustained bucket should not interfere.
		let now = now_ns();
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(10.0),
			rate_limit_burst: Some(5.0),
			..Default::default()
		});
		let peer = ip("4.0.0.3");

		// 5 connections drain the per-second burst, but no sustained limit → blocked on #6 by per-second only
		for _ in 0..5 {
			assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Allow(_)));
			state.release(peer);
		}
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::RateLimited)));
	}

	// ── Penalty box tests ──────────────────────────────────────────────────────

	#[test]
	fn penalty_box_entered_on_rate_limit_exhaustion() {
		let now = now_ns();
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(100.0),
			rate_limit_burst: Some(1.0), // burst_fp=1000, ONE_TOKEN=1000 → one connection allowed
			penalty_box_duration_ms: 60_000,
			..Default::default()
		});
		let peer = ip("5.0.0.1");

		// First connection consumes the only token
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Allow(_)));
		state.release(peer);

		// Second: bucket exhausted → RateLimited + penalty box entered
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::RateLimited)));

		// Third: penalty box is now active → PenaltyBoxed
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::PenaltyBoxed)));
	}

	#[test]
	fn penalty_box_sustained_exhaustion_enters_box() {
		let now = now_ns();
		let state = ProtectionState::new(ProtectionConfig {
			// Generous per-second limit so per-second bucket never exhausts
			rate_limit_cps: Some(1000.0),
			rate_limit_burst: Some(1000.0),
			sustained_cpm: Some(600.0),
			sustained_burst: Some(1.0), // 1 connection burst
			penalty_box_duration_ms: 60_000,
			..Default::default()
		});
		let peer = ip("5.0.0.2");

		// Consumes the single sustained token
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Allow(_)));
		state.release(peer);

		// Sustained exhausted → RateLimited + penalty entered
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::RateLimited)));

		// Now penalized
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::PenaltyBoxed)));
	}

	#[test]
	fn penalty_box_blocks_while_active() {
		let now = now_ns();
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(100.0),
			rate_limit_burst: Some(1.0),
			penalty_box_duration_ms: 60_000,
			..Default::default()
		});
		let peer = ip("5.0.0.3");

		// Enter the penalty box
		state.check_at(peer, &no_peek(), now); // Allow (consume token)
		state.release(peer);
		state.check_at(peer, &no_peek(), now); // Block(RateLimited) — enters penalty box

		// Well within penalty window
		let mid = now + 30_000_000_000; // 30s later, penalty is 60s
		assert!(matches!(state.check_at(peer, &no_peek(), mid), Decision::Block(BlockReason::PenaltyBoxed)));
	}

	#[test]
	fn penalty_box_extends_on_continued_excess() {
		// With only per-second limit enabled, a bucket that is always-empty (burst < ONE_TOKEN)
		// will extend the penalty on every check while boxed.
		let now = now_ns();
		let penalty_ms: u64 = 10_000; // 10 s
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(100.0),
			// burst_fp=500 < ONE_TOKEN=1000 → consume always fails while boxed
			rate_limit_burst: Some(0.5),
			penalty_box_duration_ms: penalty_ms,
			..Default::default()
		});
		let peer = ip("5.0.0.4");

		// Exhaust bucket (tokens=0 initially since burst_fp < ONE_TOKEN) → RateLimited → enter box
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::RateLimited)));

		// Deadline should be set to now + penalty_ms * 1_000_000
		let state_entry = state.ip_table.get(&peer).unwrap();
		let deadline_after_entry = state_entry.penalty_deadline_ns.load(Ordering::Relaxed);
		assert_eq!(deadline_after_entry, now.saturating_add(penalty_ms.saturating_mul(1_000_000)));
		drop(state_entry);

		// 5s later — still within penalty; bucket still empty → should extend
		let t1 = now + 5_000_000_000; // 5s
		assert!(matches!(state.check_at(peer, &no_peek(), t1), Decision::Block(BlockReason::PenaltyBoxed)));

		let state_entry = state.ip_table.get(&peer).unwrap();
		let deadline_after_extend = state_entry.penalty_deadline_ns.load(Ordering::Relaxed);
		drop(state_entry);

		// Deadline must have been pushed to t1 + penalty_ms * 1_000_000
		assert_eq!(deadline_after_extend, t1.saturating_add(penalty_ms.saturating_mul(1_000_000)));
		assert!(deadline_after_extend > deadline_after_entry, "deadline must have been extended");
	}

	#[test]
	fn penalty_box_no_extension_if_bucket_refilled() {
		// If the IP stops attacking, the bucket refills and debit succeeds while boxed.
		// The deadline should NOT be extended.
		let penalty_ms: u64 = 60_000; // 60s
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(1.0),
			rate_limit_burst: Some(1.0), // burst_fp=1000
			penalty_box_duration_ms: penalty_ms,
			..Default::default()
		});
		let peer = ip("5.0.0.5");
		let now = now_ns();

		// Consume the token → rate limited → enter box
		state.check_at(peer, &no_peek(), now); // Allow
		state.release(peer);
		state.check_at(peer, &no_peek(), now); // Block → enter penalty

		let state_entry = state.ip_table.get(&peer).unwrap();
		let deadline_after_entry = state_entry.penalty_deadline_ns.load(Ordering::Relaxed);
		drop(state_entry);

		// 30s later (half of penalty). At 1 cps, 30s refills 30 tokens → bucket=30 > ONE_TOKEN.
		// Debit succeeds → no extension.
		let t1 = now + 30_000_000_000; // 30s
		assert!(matches!(state.check_at(peer, &no_peek(), t1), Decision::Block(BlockReason::PenaltyBoxed)));

		let state_entry = state.ip_table.get(&peer).unwrap();
		let deadline_no_extend = state_entry.penalty_deadline_ns.load(Ordering::Relaxed);
		drop(state_entry);

		assert_eq!(deadline_no_extend, deadline_after_entry, "deadline must not change when bucket refilled");
	}

	#[test]
	fn penalty_box_expires_and_readmits() {
		let penalty_ms: u64 = 5_000; // 5s in this test
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(100.0),
			rate_limit_burst: Some(1.0), // single-token burst
			penalty_box_duration_ms: penalty_ms,
			..Default::default()
		});
		let peer = ip("5.0.0.6");
		let now = now_ns();

		// Enter penalty box
		state.check_at(peer, &no_peek(), now); // Allow
		state.release(peer);
		state.check_at(peer, &no_peek(), now); // RateLimited → box entered

		// Immediately still blocked
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::PenaltyBoxed)));

		// After penalty_ms + some margin, deadline has passed → readmitted
		// Also advance enough time for the per-second bucket to refill (at 100 cps, 0.01s fills 1 token)
		let after_penalty = now + (penalty_ms + 1000) * 1_000_000; // penalty + 1 second
		assert!(matches!(state.check_at(peer, &no_peek(), after_penalty), Decision::Allow(_)));
		state.release(peer);
	}

	#[test]
	fn penalty_box_disabled_by_default() {
		// With no penalty_box_duration_ms, exhausting the rate limit only blocks the current
		// connection — the next one is not pre-emptively blocked.
		let now = now_ns();
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(100.0),
			// burst_fp=500 < ONE_TOKEN → always blocked when empty
			rate_limit_burst: Some(0.5),
			// penalty_box_duration_ms = 0 (default)
			..Default::default()
		});
		let peer = ip("5.0.0.7");

		// Blocked by rate limit (no penalty)
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::RateLimited)));
		// Still rate limited, but NOT PenaltyBoxed — penalty box is off
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::RateLimited)));
	}

	// ── Fix 1: u64 overflow with absurd penalty duration ──────────────────────

	#[test]
	fn penalty_box_absurd_duration_still_engages() {
		// A "ban forever" duration near u64::MAX would overflow now + penalty_ms * 1_000_000
		// without saturating arithmetic, wrapping to a past deadline and silently never
		// engaging the box. saturating_add/saturating_mul must clamp to u64::MAX instead.
		let now: u64 = 1_000_000_000; // 1 s into process life
		let absurd_ms: u64 = u64::MAX / 1_000_000 + 1; // multiplying by 1_000_000 overflows
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(100.0),
			rate_limit_burst: Some(1.0),
			penalty_box_duration_ms: absurd_ms,
			..Default::default()
		});
		let peer = ip("7.0.0.1");

		// Consume token → rate limited → penalty entered with saturated deadline
		state.check_at(peer, &no_peek(), now); // Allow
		state.release(peer);
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::RateLimited)));

		// Verify deadline is u64::MAX (saturated), not a wrapped past value
		let state_entry = state.ip_table.get(&peer).unwrap();
		let deadline = state_entry.penalty_deadline_ns.load(Ordering::Relaxed);
		drop(state_entry);
		assert_eq!(deadline, u64::MAX, "absurd duration must saturate to u64::MAX, not wrap");

		// Box must now engage (now < u64::MAX)
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::PenaltyBoxed)));
		// And at a much later time still far below u64::MAX, still blocked
		assert!(matches!(
			state.check_at(peer, &no_peek(), now + 86_400_000_000_000),
			Decision::Block(BlockReason::PenaltyBoxed)
		));
	}

	// ── Fix 4: blockedIps() respects config after hot-swap disables penaltyBox ─

	#[test]
	fn blocked_ips_penalty_boxed_gated_on_config() {
		let now = now_ns();
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(100.0),
			rate_limit_burst: Some(0.5), // always blocked
			penalty_box_duration_ms: 600_000,
			..Default::default()
		});
		let peer = ip("8.0.0.1");

		// Enter the penalty box
		state.check_at(peer, &no_peek(), now);

		// Confirm it's reported
		let (_, _, pb) = state.blocked_ips();
		assert!(pb.contains(&peer), "IP must appear in penaltyBoxed while box is enabled");

		// Hot-swap: disable penalty box
		state.config.store(Arc::new(
			ProtectionConfig {
				rate_limit_cps: Some(100.0),
				rate_limit_burst: Some(0.5),
				penalty_box_duration_ms: 0, // disabled
				..Default::default()
			}
			.precompute(),
		));

		// IP still has a non-zero deadline on its IpState (stale), but config says disabled
		let (_, _, pb_after) = state.blocked_ips();
		assert!(
			pb_after.is_empty(),
			"penaltyBoxed must be empty after hot-swap disables penaltyBox config; got: {pb_after:?}"
		);
	}

	// ── Fix 5: blockedIps() rate-limited uses lazy projection ──────────────────

	#[test]
	fn blocked_ips_rate_limited_excludes_recovered_ips() {
		let now = now_ns();
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(1000.0), // fast refill: 1000 tokens/s
			rate_limit_burst: Some(1.0),  // burst_fp=1000
			..Default::default()
		});
		let peer = ip("8.0.0.2");

		// Exhaust bucket
		state.check_at(peer, &no_peek(), now); // Allow — consumes last token
		state.release(peer);
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::RateLimited)));

		// At now+0 the stored token value is 0 (below ONE_TOKEN=1000) — stale check would
		// report the IP as still limited. Lazy projection must exclude it at t=now+2ms
		// (2ms @ 1000cps = 2000 fp refill, capped at burst_fp=1000 → fully recovered).
		let recovered = now + 2_000_000; // 2 ms later
		let (rl, _, _) = state.blocked_ips_at(recovered);
		assert!(!rl.contains(&peer), "recovered IP must not appear in rateLimited; got: {rl:?}");
	}

	// ── Fix 6: evict vs active-counter race (Arc-held decrement) ──────────────

	#[test]
	fn active_guard_arc_release_survives_eviction() {
		// Simulate the race: check() returns Allow(Arc<IpState>), then evict() removes the
		// entry from the map, then the held Arc releases the active counter.
		// With the pre-fix implementation, release() would re-look-up by IP and decrement
		// a fresh (zero-active) entry. With the fix, the held Arc is decremented directly.
		let state = ProtectionState::new(ProtectionConfig {
			max_concurrent_per_ip: 10,
			..Default::default()
		});
		let peer = ip("9.0.0.1");
		let now = now_ns();

		// Admit the connection, holding the Arc<IpState>
		let held_arc = match state.check_at(peer, &no_peek(), now) {
			Decision::Allow(s) => s,
			other => panic!("expected Allow, got {other:?}"),
		};
		assert_eq!(held_arc.active.load(Ordering::Relaxed), 1, "active must be 1 after check");

		// Forcibly evict the entry (simulating the race: evict runs after check but before release)
		state.ip_table.remove(&peer);
		assert!(state.ip_table.get(&peer).is_none(), "entry must be gone from map");

		// Release through the held Arc — must decrement the SAME IpState, not a re-inserted one
		held_arc.release();
		assert_eq!(held_arc.active.load(Ordering::Relaxed), 0, "active on held Arc must be 0 after release");

		// A new check should get a fresh entry with active=0, not a poisoned one
		let d2 = state.check_at(peer, &no_peek(), now);
		assert!(matches!(d2, Decision::Allow(_)), "fresh entry after evict must allow");
		if let Decision::Allow(s2) = d2 {
			assert_eq!(s2.active.load(Ordering::Relaxed), 1, "fresh entry active must be 1");
			s2.release();
		}
	}

	// ── Eviction tests ─────────────────────────────────────────────────────────

	#[test]
	fn evict_removes_idle_no_rate_limit_entry() {
		// No rate limit configured (burst_fp=0, sustained_burst_fp=0).
		// An entry created for concurrency tracking only should be evicted when idle.
		let state = ProtectionState::new(ProtectionConfig {
			max_concurrent_per_ip: 10,
			..Default::default()
		});
		let peer = ip("6.0.0.1");
		let now = now_ns();

		state.check_at(peer, &no_peek(), now); // Allow (active=1)
		state.release(peer); // active=0

		assert_eq!(state.ip_table.len(), 1);
		state.evict_at(now);
		assert_eq!(state.ip_table.len(), 0, "idle entry with no rate limit must be evicted");
	}

	#[test]
	fn evict_removes_rate_limited_entry_after_refill_window() {
		// After draining 1 token from a burst-10 bucket at 100 cps, the entry is idle.
		// evict_at(now) retains it; evict_at(now + large) sees it as fully refilled → evicts.
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(100.0),
			rate_limit_burst: Some(10.0), // burst_fp = 10000; 10 tokens
			..Default::default()
		});
		let peer = ip("6.0.0.11");
		let now = now_ns();

		state.check_at(peer, &no_peek(), now); // Allow — drains 1 token
		state.release(peer); // active=0

		// Immediately: tokens = 9000 < 10000 → retained
		state.evict_at(now);
		assert_eq!(state.ip_table.len(), 1);

		// 0.2 s later: at 100 cps, 9000 fp deficit (1 token) refills in 0.01 s.
		// Lazy projection: current=9000 + refill(200ms@100cps)=20000 → capped at 10000 == burst_fp → evict.
		state.evict_at(now + 200_000_000); // 200 ms
		assert_eq!(state.ip_table.len(), 0, "rate-limited idle entry must be evicted after refill window");
	}

	#[test]
	fn evict_retains_penalty_boxed_entries() {
		let now = now_ns();
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(100.0),
			rate_limit_burst: Some(0.5), // always rate-limited (burst_fp=500 < ONE_TOKEN=1000)
			penalty_box_duration_ms: 600_000, // 10 min
			..Default::default()
		});
		let peer = ip("6.0.0.2");

		// Enter penalty box
		state.check_at(peer, &no_peek(), now); // RateLimited → box entered
		assert_eq!(state.ip_table.len(), 1);

		// Even with a huge future time, the penalty box check runs first → retained
		state.evict_at(now + 60_000_000_000); // 60 s (still within 10 min penalty)
		assert_eq!(state.ip_table.len(), 1, "penalty-boxed entry must not be evicted");
	}

	#[test]
	fn evict_retains_entries_with_depleted_sustained_bucket() {
		let now = now_ns();
		let state = ProtectionState::new(ProtectionConfig {
			// No per-second limit — only sustained, so only that check can block
			sustained_cpm: Some(60.0),
			sustained_burst: Some(2.0),
			..Default::default()
		});
		let peer = ip("6.0.0.3");

		// Exhaust sustained bucket (2 connections)
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Allow(_)));
		state.release(peer);
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Allow(_)));
		state.release(peer);
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::RateLimited)));

		assert_eq!(state.ip_table.len(), 1);

		// At `now`: sustained refill = 0 → would_be < burst_fp → retained (attacker history preserved)
		state.evict_at(now);
		assert_eq!(state.ip_table.len(), 1, "entry with depleted sustained bucket must not be evicted");

		// 1 second later: at 60 CPM = 1 per second, 1 s refills 1 token.
		// burst=2, so 2 tokens were drained (2000 fp). In 1 s: refill=1*1/60*60*1000 = 1000 fp.
		// current=0 + refill=1000 = 1000 < burst_fp=2000 → still retained
		state.evict_at(now + 1_000_000_000); // 1 s
		assert_eq!(state.ip_table.len(), 1, "entry still recovering after 1s must not be evicted");

		// 3 seconds later: at 60 CPM, 3 s refills 3 tokens = 3000 fp > 2000 → capped at 2000 → evict
		state.evict_at(now + 3_000_000_000); // 3 s
		assert_eq!(state.ip_table.len(), 0, "fully-refilled sustained entry must be evicted");
	}

	#[test]
	fn evict_retains_entries_with_active_connections() {
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(100.0),
			rate_limit_burst: Some(100.0),
			..Default::default()
		});
		let peer = ip("6.0.0.4");
		let now = now_ns();

		// Allow and do NOT release — active counter remains 1
		let held = match state.check_at(peer, &no_peek(), now) {
			Decision::Allow(s) => s,
			other => panic!("expected Allow, got {other:?}"),
		};

		assert_eq!(state.ip_table.len(), 1);
		// Even with a long future time, the active=1 guard keeps it
		state.evict_at(now + 86_400_000_000_000); // 1 day
		assert_eq!(state.ip_table.len(), 1, "entry with active connections must not be evicted");

		// Clean up
		held.release();
	}

	// ── Fix 2: stale penalty deadline eviction after penaltyBox disable/re-enable ─

	#[test]
	fn evict_clears_stale_penalty_after_penaltybox_disabled() {
		// Box an IP, then hot-swap penaltyBox off, evict with fully-refilled buckets,
		// re-enable — re-enabled penaltyBox must not resurrect the pre-disable deadline.
		let now = now_ns();
		let penalty_ms: u64 = 60_000; // 60 s
		let state = ProtectionState::new(ProtectionConfig {
			rate_limit_cps: Some(100.0),
			rate_limit_burst: Some(1.0), // burst_fp=1000 = ONE_TOKEN
			penalty_box_duration_ms: penalty_ms,
			..Default::default()
		});
		let peer = ip("6.0.0.5");

		// Consume the only token → rate limited → penalty box entered with deadline = now + 60s
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Allow(_)));
		state.release(peer);
		assert!(matches!(state.check_at(peer, &no_peek(), now), Decision::Block(BlockReason::RateLimited)));

		// Verify entry is present and IP is in penalty box
		assert!(state.ip_table.contains_key(&peer));
		let (_, _, pb) = state.blocked_ips_at(now + 1_000_000);
		assert!(pb.contains(&peer), "IP must be in penalty box before disable");

		// Hot-swap: disable penalty box
		state.config.store(Arc::new(
			ProtectionConfig {
				rate_limit_cps: Some(100.0),
				rate_limit_burst: Some(1.0),
				penalty_box_duration_ms: 0, // disabled
				..Default::default()
			}
			.precompute(),
		));

		// Evict at a time far enough in the future that the per-second bucket is fully
		// refilled (100 cps × 120s >>> burst_fp=1000). With penaltyBox disabled, the
		// stale deadline must NOT prevent eviction.
		let far_future = now + 120_000_000_000; // 2 min
		state.evict_at(far_future);
		assert!(
			!state.ip_table.contains_key(&peer),
			"entry must be evicted when penaltyBox disabled and buckets fully refilled"
		);

		// Re-enable penalty box — the pre-disable deadline is gone (entry evicted).
		state.config.store(Arc::new(
			ProtectionConfig {
				rate_limit_cps: Some(100.0),
				rate_limit_burst: Some(1.0),
				penalty_box_duration_ms: penalty_ms,
				..Default::default()
			}
			.precompute(),
		));

		// IP must be admitted fresh — no stale deadline blocks it
		assert!(
			matches!(state.check_at(peer, &no_peek(), far_future), Decision::Allow(_)),
			"IP must be admitted fresh after re-enable; stale deadline must not resurrect"
		);
	}
}
