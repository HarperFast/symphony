//! Peer failover: while a route's local upstream is down (or the route is draining), forward its
//! new connections, still as raw TLS, to a peer node's failover ingress listener. With `spill`, also
//! forward a share of them while the local Harper threads are much busier than a peer's.

use crate::balancer::SlotHealth;
use crate::metrics::{CountingStream, ErrorKind, PeerFailureKind};
use crate::protection::now_ns;
use crate::proxy_conn::{emit, forward_opaque, ConnContext, JsEvent};
use crate::router::{Destination, LiveRouteTable, RouteMetricIdentity};
use crate::sni::PeekInfo;
use napi::threadsafe_function::ThreadsafeFunction;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio::time::{timeout, Instant};

const DEFAULT_PROBE_INTERVAL_MS: f64 = 1_000.0;
const DEFAULT_COOLDOWN_MIN_MS: f64 = 5_000.0;
const DEFAULT_COOLDOWN_MAX_MS: f64 = 60_000.0;
const MIN_PROBE_INTERVAL_MS: f64 = 10.0;
const MAX_INTERVAL_MS: f64 = 86_400_000.0;
/// One probe connect's limit, independent of `probeIntervalMs`: a short interval must not turn a
/// slow accept into a refusal that keeps the route failed over.
const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
/// Longest the probe task sleeps, so a reload that shortens `probeIntervalMs` takes effect promptly.
const MAX_PROBE_TICK: Duration = Duration::from_secs(1);
const MAX_CONCURRENT_PROBES: usize = 64;
/// While the local upstream is up, a forward no peer answers is served locally with what is left
/// of the handshake timeout, so the attempts take at most half of it, and at most this.
const DRAIN_BUDGET: Duration = Duration::from_secs(2);
const SPILL_BUDGET: Duration = Duration::from_secs(1);
/// Load queries go out at most this often, however short `probeIntervalMs` is.
const MIN_LOAD_POLL: Duration = Duration::from_millis(100);
/// The controller runs at least this often: under a local sample's validity (1 s) by a margin, so
/// the admission it publishes is renewed before it expires.
const CONTROL_TICK: Duration = Duration::from_millis(250);
const MIN_REPORT_TTL_NS: u64 = 3_000_000_000;
/// Longest step the controller takes at once, so a stalled task cannot move the fraction in a jump.
const MAX_CONTROL_STEP_NS: u64 = 1_000_000_000;
const MAX_PEER_RTT_MS: f64 = 60_000.0;
const RTT_EWMA_WEIGHT: f64 = 0.25;

#[derive(Clone, Debug)]
pub struct FailoverSpec {
	pub peers: Vec<(String, u16)>,
	pub drain: bool,
	pub probe_interval_ms: Option<f64>,
	pub cooldown_min_ms: Option<f64>,
	pub cooldown_max_ms: Option<f64>,
	/// Validated apart from the rest of the policy: an invalid `spill` disables only spill.
	pub spill: Option<SpillSpec>,
}

#[derive(Debug, PartialEq)]
pub struct FailoverPolicy {
	pub peers: Vec<SocketAddr>,
	pub drain: bool,
	pub probe_interval: Duration,
	pub cooldown_min: Duration,
	pub cooldown_max: Duration,
	pub spill: Option<SpillPolicy>,
}

#[derive(Clone, Debug, Default)]
pub struct SpillSpec {
	pub high_water: Option<f64>,
	pub margin: Option<f64>,
	pub step: Option<f64>,
	pub max_fraction: Option<f64>,
	pub max_peer_rtt_ms: Option<f64>,
}

/// Thresholds in permille of one core per thread (`thread_cpu`'s unit); `step` in permille per second.
#[derive(Clone, Debug, PartialEq)]
pub struct SpillPolicy {
	pub high_water: u32,
	pub margin: u32,
	pub step: f64,
	pub max_fraction: u32,
	pub max_peer_rtt: Option<Duration>,
}

impl SpillSpec {
	pub fn parse(&self) -> Result<SpillPolicy, String> {
		// Thresholds are compared in whole permille; a value that rounds below `min` would compare
		// as 0 (a zero hold margin lets two equally loaded nodes spill to each other).
		let fraction = |value: Option<f64>, default: f64, min: f64, label: &str| {
			let v = value.unwrap_or(default);
			if !v.is_finite() || v < min || v > 1.0 {
				return Err(format!(
					"failover.spill.{label} must be between {min} and 1, got {v}"
				));
			}
			Ok(v * 1000.0)
		};
		let max_peer_rtt = match self.max_peer_rtt_ms {
			None => None,
			Some(ms) if ms.is_finite() && ms > 0.0 && ms <= MAX_PEER_RTT_MS => {
				Some(Duration::from_secs_f64(ms / 1000.0))
			}
			Some(ms) => {
				return Err(format!(
					"failover.spill.maxPeerRttMs must be in (0, {MAX_PEER_RTT_MS}], got {ms}"
				))
			}
		};
		Ok(SpillPolicy {
			high_water: fraction(self.high_water, 0.75, 0.001, "highWater")?.round() as u32,
			margin: fraction(self.margin, 0.20, 0.002, "margin")?.round() as u32,
			step: fraction(self.step, 0.05, 0.001, "step")?,
			max_fraction: fraction(self.max_fraction, 0.50, 0.001, "maxFraction")?.round() as u32,
			max_peer_rtt,
		})
	}
}

fn bounded_ms(value: Option<f64>, default: f64, min: f64, label: &str) -> Result<Duration, String> {
	let ms = value.unwrap_or(default);
	if !ms.is_finite() || !(min..=MAX_INTERVAL_MS).contains(&ms) {
		return Err(format!(
			"failover.{label} must be between {min} and {MAX_INTERVAL_MS} ms, got {ms}"
		));
	}
	Ok(Duration::from_millis(ms as u64))
}

impl FailoverSpec {
	pub fn parse(&self) -> Result<FailoverPolicy, String> {
		if self.peers.is_empty() {
			return Err("failover.peers must name at least one peer".into());
		}
		let mut peers = Vec::with_capacity(self.peers.len());
		for (host, port) in &self.peers {
			let ip: IpAddr = host.parse().map_err(|_| {
				format!("failover peer host '{host}' must be an IP literal (symphony does not resolve names)")
			})?;
			if *port == 0 {
				return Err(format!("failover peer '{host}' needs a non-zero port"));
			}
			let addr = SocketAddr::new(ip, *port);
			if peers.contains(&addr) {
				return Err(format!("failover peer '{addr}' is listed twice"));
			}
			peers.push(addr);
		}
		let probe_interval = bounded_ms(
			self.probe_interval_ms,
			DEFAULT_PROBE_INTERVAL_MS,
			MIN_PROBE_INTERVAL_MS,
			"probeIntervalMs",
		)?;
		let cooldown_min = bounded_ms(
			self.cooldown_min_ms,
			DEFAULT_COOLDOWN_MIN_MS,
			1.0,
			"peerCooldownMs.min",
		)?;
		let cooldown_max = bounded_ms(
			self.cooldown_max_ms,
			DEFAULT_COOLDOWN_MAX_MS.max(cooldown_min.as_millis() as f64),
			1.0,
			"peerCooldownMs.max",
		)?;
		if cooldown_max < cooldown_min {
			return Err("failover.peerCooldownMs.max must be at least min".into());
		}
		Ok(FailoverPolicy {
			peers,
			drain: self.drain,
			probe_interval,
			cooldown_min,
			cooldown_max,
			spill: None,
		})
	}
}

const COOLDOWN_STREAK_SHIFT: u32 = 56;
const COOLDOWN_UNTIL_MASK: u64 = (1 << COOLDOWN_STREAK_SHIFT) - 1;

/// One peer of one route. Cooldown is per (route, peer): on a shared host one tenant's Harper can
/// be down while another's is up.
pub struct FailoverPeer {
	pub addr: SocketAddr,
	/// Consecutive failures (top 8 bits) and cooldown deadline in monotonic ns (low 56 bits), one
	/// word so a success and a concurrent failure cannot leave a streak without its cooldown.
	cooldown: AtomicU64,
	/// Connections handed over because the route was down or draining.
	pub forwarded: AtomicU64,
	/// Connections handed over by spill-over. Disjoint from `forwarded`.
	pub spilled: AtomicU64,
	failures: [AtomicU64; PeerFailureKind::COUNT],
	/// The peer's last load report for this route: permille in the low 10 bits, monotonic ms it
	/// arrived above them; 0 = none, or the peer would not take a spilled connection. Written only
	/// by the load poll.
	report: AtomicU64,
	/// Smoothed connect time of the load query, in µs; 0 = not measured.
	rtt_us: AtomicU32,
}

impl FailoverPeer {
	fn new(addr: SocketAddr) -> Self {
		Self {
			addr,
			cooldown: AtomicU64::new(0),
			forwarded: AtomicU64::new(0),
			spilled: AtomicU64::new(0),
			failures: std::array::from_fn(|_| AtomicU64::new(0)),
			report: AtomicU64::new(0),
			rtt_us: AtomicU32::new(0),
		}
	}

	/// `(load permille, ms received)` of the last usable report.
	pub fn report(&self) -> Option<(u32, u64)> {
		let packed = self.report.load(Ordering::Relaxed);
		(packed != 0).then_some(((packed & 0x3FF) as u32, packed >> 10))
	}

	fn set_report(&self, load: Option<u32>, now_ms: u64) {
		let packed = load.map_or(0, |l| now_ms.max(1) << 10 | l.min(1000) as u64);
		self.report.store(packed, Ordering::Relaxed);
	}

	pub fn rtt(&self) -> Option<Duration> {
		let us = self.rtt_us.load(Ordering::Relaxed);
		(us != 0).then(|| Duration::from_micros(us as u64))
	}

	fn record_rtt(&self, sample: Duration) {
		let sample = sample.as_micros().clamp(1, u32::MAX as u128) as f64;
		let smoothed = match self.rtt_us.load(Ordering::Relaxed) {
			0 => sample,
			prev => prev as f64 + RTT_EWMA_WEIGHT * (sample - prev as f64),
		};
		self.rtt_us
			.store(smoothed.round().max(1.0) as u32, Ordering::Relaxed);
	}

	fn cooldown_until(&self) -> u64 {
		self.cooldown.load(Ordering::Relaxed) & COOLDOWN_UNTIL_MASK
	}

	pub fn cooling_down(&self, now: u64) -> bool {
		now.min(COOLDOWN_UNTIL_MASK) < self.cooldown_until()
	}

	/// Sparse, like route errors: zero-valued reasons are omitted so scrape size follows failures,
	/// not routes × peers × reasons.
	pub fn failures_by_reason(&self) -> Vec<(&'static str, u64)> {
		PeerFailureKind::ALL
			.iter()
			.map(|k| {
				(
					k.as_str(),
					self.failures[*k as usize].load(Ordering::Relaxed),
				)
			})
			.filter(|(_, count)| *count > 0)
			.collect()
	}

	fn record_failure(&self, kind: PeerFailureKind, min_ns: u64, max_ns: u64, now: u64) {
		self.failures[kind as usize].fetch_add(1, Ordering::Relaxed);
		let _ = self
			.cooldown
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |state| {
				let streak = (state >> COOLDOWN_STREAK_SHIFT).saturating_add(1).min(255);
				let backoff = min_ns
					.saturating_mul(1u64 << (streak - 1).min(63))
					.min(max_ns);
				// Concurrent failures finish in any order; the longest deadline wins.
				let until = (state & COOLDOWN_UNTIL_MASK)
					.max(now.saturating_add(backoff))
					.min(COOLDOWN_UNTIL_MASK);
				Some(streak << COOLDOWN_STREAK_SHIFT | until)
			});
	}

	fn clear_cooldown(&self) {
		self.cooldown.store(0, Ordering::Relaxed);
	}
}

/// Per-route failover state that outlives a config reload while the route's metric identity does.
#[derive(Default)]
pub struct FailoverStatus {
	/// Last health reported through `routeHealth`. Written only by the probe task.
	reported_down: AtomicBool,
	last_probe_ns: AtomicU64,
	/// Attempts that replayed the saved ClientHello to a second or later peer.
	pub replays: AtomicU64,
	/// Connections closed because every candidate peer failed within the budget.
	pub exhausted: AtomicU64,
	/// Draining or spilled connections served locally because no peer took them.
	pub local_fallbacks: AtomicU64,
}

pub struct Failover {
	pub drain: bool,
	pub probe_interval: Duration,
	cooldown_min_ns: u64,
	cooldown_max_ns: u64,
	pub peers: Box<[Arc<FailoverPeer>]>,
	cursor: AtomicUsize,
	/// Health of a TCP destination (a one-slot set); `None` for a UDS destination, whose
	/// balancer tracks each slot.
	pub tcp_health: Option<Arc<SlotHealth>>,
	pub status: Arc<FailoverStatus>,
	pub spill: Option<Spill>,
}

pub struct Spill {
	pub policy: SpillPolicy,
	pub state: Arc<SpillState>,
}

#[derive(Default)]
pub struct SpillState {
	/// What the hot path may do: fraction permille (bits 0–9), target peer index (10–25),
	/// monotonic ms until which it holds (26–63). 0 = spill nothing. One word, so a connection never
	/// pairs one controller pass's fraction with another's target.
	admission: AtomicU64,
	/// Written only by the load poll.
	controller: Mutex<Controller>,
}

#[derive(Default)]
struct Controller {
	/// Permille, moving at most `step` per second; spilling is admitted only while it is justified.
	fraction: f64,
	last_ns: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Admission {
	pub fraction: u32,
	pub target: usize,
	pub until_ms: u64,
}

impl Admission {
	fn pack(self) -> u64 {
		self.until_ms << 26 | (self.target as u64 & 0xFFFF) << 10 | self.fraction.min(1000) as u64
	}

	fn unpack(packed: u64) -> Option<Self> {
		(packed & 0x3FF != 0).then_some(Self {
			fraction: (packed & 0x3FF) as u32,
			target: ((packed >> 10) & 0xFFFF) as usize,
			until_ms: packed >> 26,
		})
	}
}

impl SpillState {
	pub fn admission(&self, now_ms: u64) -> Option<Admission> {
		Admission::unpack(self.admission.load(Ordering::Relaxed)).filter(|a| now_ms < a.until_ms)
	}

	fn controller(&self) -> std::sync::MutexGuard<'_, Controller> {
		self.controller.lock().unwrap_or_else(|e| e.into_inner())
	}
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ForwardMode {
	/// The local upstream is down: try every peer (the earliest-cooling one if all are cooling),
	/// within the whole handshake budget; nothing to fall back to.
	Down,
	/// Draining while the local upstream is up: try the ready peers, fall back to local service.
	Drain,
	/// Spill-over to one peer, falling back to local service.
	Spill(usize),
}

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
	/// An ingress connection for a route this node will not serve: close with no bytes, which
	/// sends the forwarding node on to its next peer.
	Refuse,
	Forward(ForwardMode),
	Local,
}

/// `spill` is consulted only for a client connection on a route that is up and not draining.
pub fn decide(
	ingress: bool,
	suspended: bool,
	locally_down: bool,
	drain: bool,
	spill: impl FnOnce() -> Option<usize>,
) -> Decision {
	if ingress {
		return if locally_down || drain {
			Decision::Refuse
		} else {
			Decision::Local
		};
	}
	// A suspended route's destination is whatever `resolveConnection()` returns.
	if suspended {
		return Decision::Local;
	}
	if locally_down {
		return Decision::Forward(ForwardMode::Down);
	}
	if drain {
		return Decision::Forward(ForwardMode::Drain);
	}
	spill().map_or(Decision::Local, |peer| {
		Decision::Forward(ForwardMode::Spill(peer))
	})
}

fn spill_hash(client: SocketAddr) -> u64 {
	static SALT: OnceLock<std::collections::hash_map::RandomState> = OnceLock::new();
	SALT.get_or_init(Default::default)
		.hash_one((client.ip(), client.port()))
}

impl Failover {
	/// `previous` is the same route's failover in the previous table, passed only when the route
	/// keeps its metric identity, so peer counters and cooldowns continue rather than reset.
	/// `same_load_source`: the route's load still comes from the same worker threads.
	pub fn new(
		policy: FailoverPolicy,
		previous: Option<&Failover>,
		tcp_health: Option<Arc<SlotHealth>>,
		same_load_source: bool,
	) -> Self {
		let peers = policy
			.peers
			.iter()
			.map(|addr| {
				previous
					.and_then(|p| p.peers.iter().find(|peer| peer.addr == *addr))
					.cloned()
					.unwrap_or_else(|| Arc::new(FailoverPeer::new(*addr)))
			})
			.collect();
		// Continued only under the same policy, peers and load source: a carried target index must
		// name the same peer, and a carried fraction must have been reached under the same limits
		// and for the same workers.
		let spill = policy.spill.map(|spill_policy| {
			let state = previous
				.and_then(|p| p.spill.as_ref())
				.filter(|s| {
					same_load_source
						&& s.policy == spill_policy
						&& previous.is_some_and(|p| {
							p.peers
								.iter()
								.map(|peer| peer.addr)
								.eq(policy.peers.iter().copied())
						})
				})
				.map(|s| s.state.clone())
				.unwrap_or_default();
			Spill {
				policy: spill_policy,
				state,
			}
		});
		Self {
			drain: policy.drain,
			probe_interval: policy.probe_interval,
			cooldown_min_ns: policy.cooldown_min.as_nanos() as u64,
			cooldown_max_ns: policy.cooldown_max.as_nanos() as u64,
			peers,
			cursor: AtomicUsize::new(0),
			tcp_health,
			status: previous.map(|p| p.status.clone()).unwrap_or_default(),
			spill,
		}
	}

	pub fn spill_target(&self, client: SocketAddr) -> Option<usize> {
		let spill = self.spill.as_ref()?;
		let packed = spill.state.admission.load(Ordering::Relaxed);
		if packed == 0 || spill_hash(client) % 1000 >= packed & 0x3FF {
			return None;
		}
		let admission = Admission::unpack(packed)?;
		let now = now_ns();
		(now / 1_000_000 < admission.until_ms)
			.then(|| self.peers.get(admission.target))
			.flatten()
			.filter(|peer| !peer.cooling_down(now))
			.map(|_| admission.target)
	}

	pub fn report_ttl_ms(&self) -> u64 {
		(3 * self.probe_interval.as_nanos() as u64).max(MIN_REPORT_TTL_NS) / 1_000_000
	}

	/// True when every slot of the route's default destination, or of its h2 destination, is
	/// refusing. Either is enough: a client cannot be told which protocol to negotiate.
	pub fn locally_down(
		&self,
		destination: &Destination,
		destination_h2: Option<&Destination>,
	) -> bool {
		let down = |dest: &Destination| match dest {
			Destination::UdsSet(balancer) => balancer.all_refusing(),
			Destination::Tcp(_) => self.tcp_health.as_ref().is_some_and(|h| h.refusing()),
		};
		down(destination) || destination_h2.is_some_and(down)
	}

	fn candidates_for(&self, mode: ForwardMode, now: u64) -> Vec<&FailoverPeer> {
		match mode {
			ForwardMode::Down => self.candidates(now).1.collect(),
			// A local fallback exists, so a peer in cooldown is never worth the wait.
			ForwardMode::Drain => self
				.candidates(now)
				.1
				.filter(|p| !p.cooling_down(now))
				.collect(),
			ForwardMode::Spill(i) => self
				.peers
				.get(i)
				.map(|p| p.as_ref())
				.filter(|p| !p.cooling_down(now))
				.into_iter()
				.collect(),
		}
	}

	/// Peers to try, in order, and how many: round-robin over those not cooling down; if every
	/// peer is cooling down, only the one whose cooldown ends first.
	fn candidates(&self, now: u64) -> (usize, impl Iterator<Item = &FailoverPeer>) {
		let count = self.peers.len();
		let start = if count == 1 {
			0
		} else {
			self.cursor.fetch_add(1, Ordering::Relaxed) % count
		};
		let ready = self.peers.iter().filter(|p| !p.cooling_down(now)).count();
		let earliest = (ready == 0)
			.then(|| self.peers.iter().min_by_key(|p| p.cooldown_until()))
			.flatten();
		let rotation = (0..count)
			.map(move |i| &self.peers[(start + i) % count])
			.filter(move |p| !p.cooling_down(now));
		(
			ready.max(usize::from(earliest.is_some())),
			rotation.chain(earliest).map(|p| p.as_ref()),
		)
	}
}

pub enum Forwarded {
	Done(Result<(), ErrorKind>),
	/// No peer took the connection before answering; its bytes are untouched. Carries what is
	/// left of the handshake timeout for the local handshake.
	ServeLocally(Duration),
}

/// Forward a connection whose ClientHello has only been peeked to the route's peers. Each attempt
/// sends a PROXY v2 header and the ClientHello, then waits for the peer's first byte before
/// anything is read from the client — so a peer that closes without answering received nothing a
/// retry could duplicate, and until a peer answers, the connection can still be served locally.
/// The first byte commits the attempt: whatever the peer does next, it is never undone.
#[allow(clippy::too_many_arguments)]
pub async fn forward_to_peers(
	client: &mut TcpStream,
	peek: &PeekInfo,
	failover: &Failover,
	mode: ForwardMode,
	peer_addr: SocketAddr,
	local_addr: Option<SocketAddr>,
	ctx: &ConnContext,
	route: &RouteMetricIdentity,
) -> Forwarded {
	let started = Instant::now();
	let handshake = ctx.handshake_timeout();
	let give_up = |status: &FailoverStatus| match mode {
		ForwardMode::Down => {
			status.exhausted.fetch_add(1, Ordering::Relaxed);
			Forwarded::Done(Err(ErrorKind::UpstreamConnect))
		}
		ForwardMode::Drain | ForwardMode::Spill(_) => {
			status.local_fallbacks.fetch_add(1, Ordering::Relaxed);
			Forwarded::ServeLocally(handshake.saturating_sub(started.elapsed()))
		}
	};
	if !peek.complete || peek.hello_len == 0 {
		return match mode {
			ForwardMode::Down => Forwarded::Done(Err(ErrorKind::UpstreamConnect)),
			_ => Forwarded::ServeLocally(handshake),
		};
	}
	let budget = match mode {
		// Every attempt shares the handshake budget the client would have had on this node.
		ForwardMode::Down => handshake,
		ForwardMode::Drain => (handshake / 2).min(DRAIN_BUDGET),
		ForwardMode::Spill(_) => (handshake / 2).min(SPILL_BUDGET),
	};
	let deadline = started + budget;
	let candidates = failover.candidates_for(mode, now_ns());
	if candidates.is_empty() {
		return give_up(&failover.status);
	}

	// 52: a PROXY v2 header with IPv6 addresses and no TLVs, the largest this writes.
	let mut prefix = Vec::with_capacity(52 + peek.hello_len);
	if crate::upstream::write_proxy_v2_header(&mut prefix, peer_addr, local_addr, &[])
		.await
		.is_err()
	{
		return give_up(&failover.status);
	}
	let header_len = prefix.len();
	prefix.resize(header_len + peek.hello_len, 0);
	// Peeked, not read: until a peer answers, the local handshake may still need them.
	match tokio::time::timeout_at(deadline, client.peek(&mut prefix[header_len..])).await {
		Ok(Ok(n)) if n == peek.hello_len => {}
		_ => return give_up(&failover.status),
	}

	let candidate_count = candidates.len();
	for (attempt, peer) in candidates.into_iter().enumerate() {
		let remaining = deadline.saturating_duration_since(Instant::now());
		if remaining.is_zero() {
			break;
		}
		if attempt > 0 {
			failover.status.replays.fetch_add(1, Ordering::Relaxed);
		}
		// A fair share of what is left, so one silent peer cannot spend every later peer's turn.
		let share = remaining / candidate_count.saturating_sub(attempt).max(1) as u32;
		match attempt_peer(peer.addr, &prefix, share).await {
			Ok(mut upstream) => {
				peer.clear_cooldown();
				let handed = match mode {
					ForwardMode::Spill(_) => &peer.spilled,
					ForwardMode::Down | ForwardMode::Drain => &peer.forwarded,
				};
				handed.fetch_add(1, Ordering::Relaxed);
				let mut client =
					CountingStream::new(&mut *client, &ctx.listener_metrics, Some(&route.counters));
				if client.read_exact(&mut prefix[header_len..]).await.is_err() {
					return Forwarded::Done(Err(ErrorKind::Stream));
				}
				// The replay copy is not needed once a peer answered; do not hold it for the tunnel.
				drop(prefix);
				return Forwarded::Done(
					forward_opaque(&mut client, &mut upstream, peer_addr, ctx).await,
				);
			}
			Err(kind) => {
				tracing::debug!("failover to {} failed: {}", peer.addr, kind.as_str());
				peer.record_failure(
					kind,
					failover.cooldown_min_ns,
					failover.cooldown_max_ns,
					now_ns(),
				);
			}
		}
	}
	give_up(&failover.status)
}

/// Ok once the peer has sent a byte. The byte is peeked, so the copy that follows forwards it.
async fn attempt_peer(
	addr: SocketAddr,
	prefix: &[u8],
	share: Duration,
) -> Result<TcpStream, PeerFailureKind> {
	let attempt = async {
		let mut stream = TcpStream::connect(addr).await.map_err(|e| match e.kind() {
			std::io::ErrorKind::ConnectionRefused => PeerFailureKind::Refused,
			_ => PeerFailureKind::Error,
		})?;
		let _ = stream.set_nodelay(true);
		stream
			.write_all(prefix)
			.await
			.map_err(|_| PeerFailureKind::ZeroByteClose)?;
		match stream.peek(&mut [0u8; 1]).await {
			Ok(0) | Err(_) => Err(PeerFailureKind::ZeroByteClose),
			Ok(_) => Ok(stream),
		}
	};
	timeout(share, attempt)
		.await
		.unwrap_or(Err(PeerFailureKind::Timeout))
}

// ── Recovery probe ────────────────────────────────────────────────────────────

pub struct FailoverRoute {
	pub identity: Arc<RouteMetricIdentity>,
	pub failover: Arc<Failover>,
	pub destination: Destination,
	pub destination_h2: Option<Destination>,
}

impl FailoverRoute {
	pub fn locally_down(&self) -> bool {
		self.failover
			.locally_down(&self.destination, self.destination_h2.as_ref())
	}

	pub fn slot_counts(&self) -> (usize, usize) {
		let mut refusing = 0;
		let mut total = 0;
		for dest in std::iter::once(&self.destination).chain(self.destination_h2.iter()) {
			match dest {
				Destination::UdsSet(balancer) => {
					for (_, health) in balancer.tracked_slots() {
						total += 1;
						refusing += usize::from(health.refusing());
					}
				}
				Destination::Tcp(_) => {
					total += 1;
					refusing += usize::from(
						self.failover
							.tcp_health
							.as_ref()
							.is_some_and(|h| h.refusing()),
					);
				}
			}
		}
		(refusing, total)
	}
}

#[derive(Clone, PartialEq, Eq, Hash)]
enum Endpoint {
	Uds(Arc<str>),
	Tcp(SocketAddr),
}

/// Probe each failover route's refusing slots at its `probeIntervalMs`, and report every route
/// health transition as a `routeHealth` event. This task is the only writer of the reported
/// state, so a transition is reported exactly once.
pub async fn probe_periodically(
	live: Arc<LiveRouteTable>,
	js_emit: Arc<ThreadsafeFunction<JsEvent>>,
	mut shutdown: broadcast::Receiver<()>,
) {
	loop {
		let tick = live
			.0
			.load()
			.failover_routes()
			.iter()
			.map(|r| r.failover.probe_interval)
			.min()
			.unwrap_or(MAX_PROBE_TICK)
			.min(MAX_PROBE_TICK);
		tokio::select! {
			_ = shutdown.recv() => return,
			_ = tokio::time::sleep(tick) => {}
		}
		let table = live.0.load_full();
		let routes = table.failover_routes();
		if routes.is_empty() {
			continue;
		}

		let now = now_ns();
		let mut due: HashMap<Endpoint, Vec<(Arc<SlotHealth>, u64)>> = HashMap::new();
		for route in routes {
			let status = &route.failover.status;
			let interval = route.failover.probe_interval.as_nanos() as u64;
			// The tick is the shortest interval; a route with a longer one skips ticks. Small
			// slack keeps a route whose interval equals the tick from skipping every other one.
			if now.saturating_sub(status.last_probe_ns.load(Ordering::Relaxed))
				< interval - interval / 10
			{
				continue;
			}
			// Stamped only when something is probed, so a slot that starts refusing is probed on
			// the next tick rather than up to a full interval after the last idle pass.
			let mut probed = false;
			let mut add = |endpoint: Endpoint, health: &Arc<SlotHealth>| {
				let observed = health.refused_at();
				if observed != 0 {
					probed = true;
					due.entry(endpoint)
						.or_default()
						.push((health.clone(), observed));
				}
			};
			for dest in std::iter::once(&route.destination).chain(route.destination_h2.iter()) {
				match dest {
					Destination::UdsSet(balancer) => {
						for (path, health) in balancer.tracked_slots() {
							add(Endpoint::Uds(path.clone()), health);
						}
					}
					Destination::Tcp(addr) => {
						if let Some(health) = &route.failover.tcp_health {
							add(Endpoint::Tcp(*addr), health);
						}
					}
				}
			}
			if probed {
				status.last_probe_ns.store(now, Ordering::Relaxed);
			}
		}

		// Dropping the pass on shutdown drops its JoinSet, which aborts the probes still running.
		let pass = async {
			let mut probes = JoinSet::new();
			for (endpoint, healths) in due {
				if probes.len() >= MAX_CONCURRENT_PROBES {
					probes.join_next().await;
				}
				probes.spawn(async move {
					if probe(&endpoint).await {
						for (health, observed) in healths {
							health.clear_if_unchanged(observed);
						}
					}
				});
			}
			while probes.join_next().await.is_some() {}
		};
		tokio::select! {
			_ = shutdown.recv() => return,
			_ = pass => {}
		}

		for route in routes {
			let down = route.locally_down();
			let reported = &route.failover.status.reported_down;
			if reported.load(Ordering::Relaxed) != down {
				let queued = emit(
					&js_emit,
					JsEvent::RouteHealth {
						route: route.identity.route.to_string(),
						metrics_group: route.identity.group.to_string(),
						up: !down,
					},
				);
				// A transition dropped by a full event queue is sent again next tick.
				if queued {
					reported.store(down, Ordering::Relaxed);
				}
			}
		}
	}
}

// ── Spill-over controller and load poll ──────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trend {
	Rise,
	Hold,
	Decay,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct PeerView {
	load: Option<u32>,
	report_until_ms: u64,
	cooling: bool,
	rtt: Option<Duration>,
}

/// `local` is `(permille, ms it is current until)`.
fn assess(
	policy: &SpillPolicy,
	local: Option<(u32, u64)>,
	peers: &[PeerView],
	now_ms: u64,
) -> (Trend, Option<(usize, u64)>) {
	let Some((local, local_until_ms)) = local.filter(|(_, until)| now_ms < *until) else {
		return (Trend::Decay, None);
	};
	let best = peers
		.iter()
		.enumerate()
		.filter(|(_, p)| now_ms < p.report_until_ms && !p.cooling)
		.filter(|(_, p)| {
			policy
				.max_peer_rtt
				.is_none_or(|max| p.rtt.is_some_and(|rtt| rtt <= max))
		})
		.filter_map(|(i, p)| Some((i, p.load?, p.report_until_ms)))
		.min_by_key(|(_, load, _)| *load);
	let Some((target, peer_load, report_until_ms)) = best else {
		return (Trend::Decay, None);
	};
	let until_ms = local_until_ms.min(report_until_ms);
	let margin = policy.margin;
	if local >= policy.high_water && peer_load + margin <= local {
		(Trend::Rise, Some((target, until_ms)))
	// Doubled, so an odd margin's half is not rounded down.
	} else if 2 * local + margin >= 2 * policy.high_water && 2 * peer_load + margin <= 2 * local {
		(Trend::Hold, Some((target, until_ms)))
	} else {
		(Trend::Decay, None)
	}
}

/// Step the controller and publish what the hot path may do. The fraction moves at most `step` per
/// second either way; spilling stops at once when it is no longer justified (no target).
fn control(
	spill: &Spill,
	local: Option<(u32, u64)>,
	peers: &[PeerView],
	now_ns: u64,
) -> Option<Admission> {
	let mut controller = spill.state.controller();
	let elapsed = if controller.last_ns == 0 {
		0
	} else {
		now_ns
			.saturating_sub(controller.last_ns)
			.min(MAX_CONTROL_STEP_NS)
	};
	controller.last_ns = now_ns;
	let (trend, target) = assess(&spill.policy, local, peers, now_ns / 1_000_000);
	let delta = spill.policy.step * elapsed as f64 / 1e9;
	controller.fraction = match trend {
		Trend::Rise => controller.fraction + delta,
		Trend::Hold => controller.fraction,
		Trend::Decay => controller.fraction - delta,
	}
	.clamp(0.0, spill.policy.max_fraction as f64);
	let admission = target
		.map(|(target, until_ms)| Admission {
			fraction: controller.fraction.round() as u32,
			target,
			until_ms,
		})
		.filter(|a| a.fraction > 0);
	spill
		.state
		.admission
		.store(admission.map_or(0, Admission::pack), Ordering::Relaxed);
	admission
}

/// The admitted share (0 when nothing is admitted) and its target.
pub fn spill_status(failover: &Failover, now_ns: u64) -> Option<(f64, Option<SocketAddr>)> {
	let spill = failover.spill.as_ref()?;
	Some(match spill.state.admission(now_ns / 1_000_000) {
		Some(a) => (
			a.fraction as f64 / 1000.0,
			failover.peers.get(a.target).map(|p| p.addr),
		),
		None => (0.0, None),
	})
}

/// A load query's outcome: the RTT sample, and each name's answer with the ms it arrived (`None`
/// for a name whose chunk failed).
struct LoadAnswer {
	rtt: Duration,
	loads: Vec<Option<(Option<u32>, u64)>>,
}

/// Poll each spill route's peers for their load and run the spill controllers. Separate from
/// `probe_periodically`, so a silent peer can never delay a `routeHealth` transition.
pub async fn poll_peer_loads(live: Arc<LiveRouteTable>, mut shutdown: broadcast::Receiver<()>) {
	type Done = (SocketAddr, Vec<Arc<str>>, Option<LoadAnswer>);
	let mut queries: JoinSet<Done> = JoinSet::new();
	let mut in_flight: HashMap<tokio::task::Id, SocketAddr> = HashMap::new();
	let mut last_query: HashMap<SocketAddr, u64> = HashMap::new();
	let mut next_tick = Instant::now();
	loop {
		tokio::select! {
			_ = shutdown.recv() => return,
			Some(done) = queries.join_next_with_id(), if !queries.is_empty() => {
				let table = live.0.load();
				match done {
					Ok((id, (addr, names, answer))) => {
						in_flight.remove(&id);
						apply_answer(&table, addr, &names, answer);
					}
					Err(e) => {
						in_flight.remove(&e.id());
					}
				}
				// A report that just changed (a peer now draining or busy) takes effect now.
				control_all(&table, now_ns());
				continue;
			}
			_ = tokio::time::sleep_until(next_tick) => {}
		}
		let table = live.0.load_full();
		let routes: Vec<&FailoverRoute> = table
			.failover_routes()
			.iter()
			.filter(|r| r.failover.spill.is_some())
			.collect();
		next_tick = Instant::now()
			+ routes
				.iter()
				.map(|r| r.failover.probe_interval.max(MIN_LOAD_POLL))
				.min()
				.unwrap_or(MAX_PROBE_TICK)
				.min(CONTROL_TICK);
		let now = now_ns();

		let mut due: HashMap<SocketAddr, (Vec<Arc<str>>, u64)> = HashMap::new();
		for route in &routes {
			let interval = route.failover.probe_interval.max(MIN_LOAD_POLL).as_nanos() as u64;
			for peer in route.failover.peers.iter() {
				let entry = due.entry(peer.addr).or_insert((Vec::new(), interval));
				entry.0.push(route.identity.route.clone());
				entry.1 = entry.1.min(interval);
			}
		}
		for (addr, (names, interval)) in due {
			let last = last_query.get(&addr).copied().unwrap_or(0);
			if in_flight.len() >= MAX_CONCURRENT_PROBES
				|| in_flight.values().any(|a| *a == addr)
				|| now.saturating_sub(last) < interval - interval / 10
			{
				continue;
			}
			last_query.insert(addr, now);
			let task = queries.spawn(async move {
				let answer = query_load(addr, &names).await;
				(addr, names, answer)
			});
			in_flight.insert(task.id(), addr);
		}
		last_query.retain(|addr, _| {
			routes
				.iter()
				.any(|r| r.failover.peers.iter().any(|p| p.addr == *addr))
		});
		control_all(&table, now);
	}
}

fn control_all(table: &crate::router::RouteTable, now: u64) {
	for route in table.failover_routes() {
		let Some(spill) = &route.failover.spill else {
			continue;
		};
		let ttl_ms = route.failover.report_ttl_ms();
		let peers: Vec<PeerView> = route
			.failover
			.peers
			.iter()
			.map(|p| {
				let report = p.report();
				PeerView {
					load: report.map(|(load, _)| load),
					report_until_ms: report.map_or(0, |(_, at)| at + ttl_ms),
					cooling: p.cooling_down(now),
					rtt: p.rtt(),
				}
			})
			.collect();
		let local =
			crate::router::route_load(&route.destination, route.destination_h2.as_ref(), now);
		control(spill, local, &peers, now);
	}
}

/// A failed query leaves each report to expire on its own, so one missed poll does not drop a
/// still-fresh reading; an answer of `-` clears it at once.
fn apply_answer(
	table: &crate::router::RouteTable,
	addr: SocketAddr,
	names: &[Arc<str>],
	answer: Option<LoadAnswer>,
) {
	let Some(answer) = answer else {
		return;
	};
	for route in table.failover_routes() {
		if route.failover.spill.is_none() {
			continue;
		}
		let Some(peer) = route.failover.peers.iter().find(|p| p.addr == addr) else {
			continue;
		};
		let Some(i) = names.iter().position(|n| *n == route.identity.route) else {
			continue;
		};
		peer.record_rtt(answer.rtt);
		if let Some(Some((load, at_ms))) = answer.loads.get(i) {
			peer.set_report(*load, *at_ms);
		}
	}
}

/// One load query per chunk of names, each within `PROBE_TIMEOUT`; the connect time of the first is
/// the RTT sample. `None` if the first chunk fails; a later chunk's failure leaves its names
/// unanswered and stops there.
async fn query_load(addr: SocketAddr, names: &[Arc<str>]) -> Option<LoadAnswer> {
	let mut rtt = None;
	let mut loads = Vec::with_capacity(names.len());
	for chunk in crate::ingress::load_query_chunks(names) {
		let attempt = async {
			let started = Instant::now();
			let mut stream = TcpStream::connect(addr).await.ok()?;
			let connect = started.elapsed();
			let _ = stream.set_nodelay(true);
			stream
				.write_all(&crate::ingress::encode_load_query(chunk))
				.await
				.ok()?;
			let mut answer = Vec::new();
			(&mut stream)
				.take(crate::ingress::max_load_answer_len(chunk.len()) as u64 + 1)
				.read_to_end(&mut answer)
				.await
				.ok()?;
			Some((
				connect,
				crate::ingress::parse_load_answer(&answer, chunk.len())?,
			))
		};
		let Some((connect, chunk_loads)) = timeout(PROBE_TIMEOUT, attempt).await.ok().flatten()
		else {
			break;
		};
		rtt.get_or_insert(connect);
		let at_ms = now_ns() / 1_000_000;
		loads.extend(chunk_loads.into_iter().map(|load| Some((load, at_ms))));
	}
	loads.resize(names.len(), None);
	Some(LoadAnswer { rtt: rtt?, loads })
}

/// Connect and close at once. Proves the socket accepts, not that the application behind it is
/// ready.
async fn probe(endpoint: &Endpoint) -> bool {
	match endpoint {
		Endpoint::Uds(path) => matches!(
			timeout(PROBE_TIMEOUT, UnixStream::connect(path.as_ref())).await,
			Ok(Ok(_))
		),
		Endpoint::Tcp(addr) => matches!(
			timeout(PROBE_TIMEOUT, TcpStream::connect(addr)).await,
			Ok(Ok(_))
		),
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	fn spec(peers: &[(&str, u16)]) -> FailoverSpec {
		FailoverSpec {
			peers: peers.iter().map(|(h, p)| (h.to_string(), *p)).collect(),
			drain: false,
			probe_interval_ms: None,
			cooldown_min_ms: Some(100.0),
			cooldown_max_ms: Some(1_000.0),
			spill: None,
		}
	}

	fn failover(peers: &[(&str, u16)]) -> Failover {
		Failover::new(spec(peers).parse().unwrap(), None, None, false)
	}

	#[test]
	fn parse_applies_defaults_and_rejects_bad_values() {
		let policy = FailoverSpec {
			cooldown_min_ms: None,
			cooldown_max_ms: None,
			..spec(&[("10.0.0.2", 9443), ("::1", 9443)])
		}
		.parse()
		.unwrap();
		assert_eq!(policy.probe_interval, Duration::from_millis(1_000));
		assert_eq!(policy.cooldown_min, Duration::from_millis(5_000));
		assert_eq!(policy.cooldown_max, Duration::from_millis(60_000));
		assert_eq!(policy.peers[1], "[::1]:9443".parse().unwrap());

		assert!(spec(&[]).parse().is_err(), "no peers");
		assert!(spec(&[("peer.example", 9443)]).parse().is_err(), "hostname");
		assert!(spec(&[("10.0.0.2", 0)]).parse().is_err(), "port 0");
		assert!(
			spec(&[("10.0.0.2", 1), ("10.0.0.2", 1)]).parse().is_err(),
			"duplicate"
		);
		for bad in [0.0, 5.0, f64::NAN, f64::INFINITY] {
			let s = FailoverSpec {
				probe_interval_ms: Some(bad),
				..spec(&[("10.0.0.2", 1)])
			};
			assert!(s.parse().is_err(), "probeIntervalMs {bad}");
		}
		let inverted = FailoverSpec {
			cooldown_min_ms: Some(2_000.0),
			cooldown_max_ms: Some(1_000.0),
			..spec(&[("10.0.0.2", 1)])
		};
		assert!(inverted.parse().is_err(), "max below min");
	}

	#[test]
	fn cooldown_doubles_to_its_cap_and_resets_on_success() {
		let fo = failover(&[("10.0.0.2", 1)]);
		let peer = &fo.peers[0];
		let ms = 1_000_000u64;
		let mut until = Vec::new();
		for _ in 0..6 {
			peer.record_failure(PeerFailureKind::Refused, 100 * ms, 1_000 * ms, 0);
			until.push(peer.cooldown_until() / ms);
		}
		assert_eq!(until, vec![100, 200, 400, 800, 1_000, 1_000]);
		assert!(peer.cooling_down(999 * ms));
		peer.clear_cooldown();
		assert!(!peer.cooling_down(0));
		peer.record_failure(PeerFailureKind::Refused, 100 * ms, 1_000 * ms, 0);
		assert_eq!(
			peer.cooldown_until() / ms,
			100,
			"backoff restarts at min after a success"
		);
	}

	#[test]
	fn a_failure_with_an_earlier_clock_does_not_shorten_the_cooldown() {
		let fo = failover(&[("10.0.0.2", 1)]);
		let peer = &fo.peers[0];
		peer.record_failure(PeerFailureKind::Refused, 100, 1_000, 500);
		// Raced in with a `now` read before the first one's.
		peer.record_failure(PeerFailureKind::Refused, 100, 1_000, 0);
		assert_eq!(peer.cooldown_until(), 600);
	}

	#[test]
	fn failures_are_reported_sparsely() {
		let fo = failover(&[("10.0.0.2", 1)]);
		let peer = &fo.peers[0];
		assert!(peer.failures_by_reason().is_empty());
		peer.record_failure(PeerFailureKind::ZeroByteClose, 1, 1, 0);
		assert_eq!(peer.failures_by_reason(), vec![("zero_byte_close", 1)]);
	}

	#[test]
	fn backoff_saturates_over_a_long_outage() {
		let fo = failover(&[("10.0.0.2", 1)]);
		let peer = &fo.peers[0];
		for _ in 0..200 {
			peer.record_failure(
				PeerFailureKind::Timeout,
				u64::MAX / 2,
				u64::MAX,
				u64::MAX - 5,
			);
		}
		assert_eq!(peer.cooldown_until(), COOLDOWN_UNTIL_MASK);
	}

	#[test]
	fn candidates_rotate_and_skip_peers_in_cooldown() {
		let fo = failover(&[("10.0.0.1", 1), ("10.0.0.2", 1), ("10.0.0.3", 1)]);
		let addrs = |(count, c): (usize, _)| {
			let c: Vec<_> = Iterator::map(c, |p: &FailoverPeer| p.addr.ip().to_string()).collect();
			assert_eq!(count, c.len());
			c
		};
		assert_eq!(
			addrs(fo.candidates(0)),
			["10.0.0.1", "10.0.0.2", "10.0.0.3"]
		);
		assert_eq!(
			addrs(fo.candidates(0)),
			["10.0.0.2", "10.0.0.3", "10.0.0.1"]
		);

		fo.peers[2].record_failure(PeerFailureKind::Refused, 10, 10, 100);
		assert_eq!(addrs(fo.candidates(105)), ["10.0.0.1", "10.0.0.2"]);
		assert_eq!(addrs(fo.candidates(110)).len(), 3, "cooldown over");
	}

	#[test]
	fn all_peers_cooling_down_yields_the_one_that_ends_first() {
		let fo = failover(&[("10.0.0.1", 1), ("10.0.0.2", 1)]);
		fo.peers[0].record_failure(PeerFailureKind::Refused, 50, 50, 100);
		fo.peers[1].record_failure(PeerFailureKind::Refused, 20, 20, 100);
		let (count, c) = fo.candidates(101);
		let c: Vec<_> = c.collect();
		assert_eq!((count, c.len()), (1, 1));
		assert_eq!(c[0].addr.ip().to_string(), "10.0.0.2");
	}

	#[test]
	fn a_rebuild_keeps_peer_state_for_unchanged_peers() {
		let old = failover(&[("10.0.0.1", 1), ("10.0.0.2", 1)]);
		old.peers[0].forwarded.fetch_add(1, Ordering::Relaxed);
		old.status.replays.fetch_add(3, Ordering::Relaxed);
		let new = Failover::new(
			spec(&[("10.0.0.1", 1), ("10.0.0.3", 1)]).parse().unwrap(),
			Some(&old),
			None,
			true,
		);
		assert!(Arc::ptr_eq(&new.peers[0], &old.peers[0]));
		assert_eq!(new.peers[0].forwarded.load(Ordering::Relaxed), 1);
		assert_eq!(new.peers[1].forwarded.load(Ordering::Relaxed), 0);
		assert_eq!(new.status.replays.load(Ordering::Relaxed), 3);
	}

	#[test]
	fn tcp_destination_is_down_only_while_its_health_refuses() {
		let health = Arc::new(SlotHealth::default());
		let fo = Failover::new(
			spec(&[("10.0.0.1", 1)]).parse().unwrap(),
			None,
			Some(health.clone()),
			false,
		);
		let dest = Destination::Tcp("127.0.0.1:1".parse().unwrap());
		assert!(!fo.locally_down(&dest, None));
		health.mark_refused();
		assert!(fo.locally_down(&dest, None));
		let observed = health.refused_at();
		std::thread::sleep(Duration::from_millis(1));
		health.mark_refused();
		assert!(
			!health.clear_if_unchanged(observed),
			"a probe must not clear a refusal newer than the one it observed"
		);
		assert!(health.clear_if_unchanged(health.refused_at()));
		assert!(!fo.locally_down(&dest, None));
	}

	// ── Spill-over ──

	const S: u64 = 1_000_000_000;

	fn policy() -> SpillPolicy {
		SpillSpec::default().parse().unwrap()
	}

	fn spill_failover(peers: &[(&str, u16)], spill: SpillPolicy) -> Failover {
		let mut policy = spec(peers).parse().unwrap();
		policy.spill = Some(spill);
		Failover::new(policy, None, None, false)
	}

	fn peer(load: u32, now_ms: u64) -> PeerView {
		PeerView {
			load: Some(load),
			report_until_ms: now_ms + 3_000,
			cooling: false,
			rtt: Some(Duration::from_millis(1)),
		}
	}

	/// Run the controller once a second for `secs` seconds from `start`, with a fresh local load.
	fn run(
		spill: &Spill,
		local: u32,
		peers: &[PeerView],
		start: u64,
		secs: u64,
	) -> Option<Admission> {
		let mut last = None;
		for i in 0..=secs {
			let now = start + i * S;
			let peers: Vec<PeerView> = peers
				.iter()
				.map(|p| PeerView {
					report_until_ms: now / 1_000_000 + 3_000,
					..*p
				})
				.collect();
			last = control(spill, Some((local, now / 1_000_000 + 1_000)), &peers, now);
		}
		last
	}

	#[test]
	fn spill_policy_defaults_and_bounds() {
		let p = policy();
		assert_eq!((p.high_water, p.margin, p.max_fraction), (750, 200, 500));
		assert_eq!(p.step, 50.0);
		assert_eq!(p.max_peer_rtt, None);
		for bad in [0.0, 0.0004, -0.1, 1.5, f64::NAN, f64::INFINITY] {
			for field in 0..4 {
				let mut s = SpillSpec::default();
				*[
					&mut s.high_water,
					&mut s.margin,
					&mut s.step,
					&mut s.max_fraction,
				][field] = Some(bad);
				assert!(s.parse().is_err(), "field {field} = {bad}");
			}
		}
		for bad in [0.0, -1.0, 60_001.0, f64::NAN] {
			let s = SpillSpec {
				max_peer_rtt_ms: Some(bad),
				..Default::default()
			};
			assert!(s.parse().is_err(), "maxPeerRttMs {bad}");
		}
		let half_margin_rounds_to_zero = SpillSpec {
			margin: Some(0.001),
			..Default::default()
		};
		assert!(half_margin_rounds_to_zero.parse().is_err());
		let s = SpillSpec {
			max_peer_rtt_ms: Some(20.0),
			..Default::default()
		};
		assert_eq!(
			s.parse().unwrap().max_peer_rtt,
			Some(Duration::from_millis(20))
		);
	}

	#[test]
	fn the_share_rises_under_sustained_high_load_toward_a_lower_peer_and_is_capped() {
		let fo = spill_failover(&[("10.0.0.1", 1), ("10.0.0.2", 1)], policy());
		let spill = fo.spill.as_ref().unwrap();
		let peers = [peer(500, 0), peer(300, 0)];

		let after_two = run(spill, 900, &peers, S, 2).unwrap();
		assert_eq!(after_two.fraction, 100, "0.05 per second");
		assert_eq!(after_two.target, 1, "the least-loaded peer");

		let capped = run(spill, 900, &peers, 10 * S, 60).unwrap();
		assert_eq!(capped.fraction, 500, "maxFraction");
	}

	#[test]
	fn the_share_decays_when_load_clears_and_spilling_stops_at_once() {
		let fo = spill_failover(&[("10.0.0.1", 1)], policy());
		let spill = fo.spill.as_ref().unwrap();
		run(spill, 900, &[peer(200, 0)], S, 6).unwrap();
		assert_eq!(spill.state.controller().fraction.round(), 300.0);

		// Load falls below highWater − margin/2: no admission from the first pass.
		assert_eq!(run(spill, 600, &[peer(200, 0)], 8 * S, 0), None);
		assert_eq!(spill.state.admission(8_000), None);
		assert_eq!(spill.state.admission.load(Ordering::Relaxed), 0);
		// 250 after that pass; four more seconds at 0.05/s.
		run(spill, 600, &[peer(200, 0)], 9 * S, 3);
		assert_eq!(
			spill.state.controller().fraction.round(),
			50.0,
			"decays at step/s"
		);
		run(spill, 600, &[peer(200, 0)], 13 * S, 5);
		assert_eq!(spill.state.controller().fraction, 0.0);
	}

	#[test]
	fn nothing_spills_when_no_peer_is_below_the_margin() {
		let fo = spill_failover(&[("10.0.0.1", 1), ("10.0.0.2", 1)], policy());
		let spill = fo.spill.as_ref().unwrap();
		assert_eq!(run(spill, 950, &[peer(950, 0), peer(1000, 0)], S, 30), None);
		assert_eq!(
			run(spill, 950, &[peer(760, 0)], 40 * S, 30),
			None,
			"gap under margin/2"
		);
		assert_eq!(spill.state.controller().fraction, 0.0);
	}

	#[test]
	fn a_held_share_needs_half_the_margin_and_goes_with_it() {
		let fo = spill_failover(&[("10.0.0.1", 1)], policy());
		let spill = fo.spill.as_ref().unwrap();
		run(spill, 900, &[peer(500, 0)], S, 4);
		// Gap 150: under margin (200) so no rise, over margin/2 (100) so the share holds.
		let held = run(spill, 850, &[peer(700, 0)], 6 * S, 3).unwrap();
		assert_eq!(held.fraction, 200);
		// Gap 50: the peer is no longer far enough below, so nothing is admitted.
		assert_eq!(run(spill, 850, &[peer(800, 0)], 10 * S, 0), None);
	}

	#[test]
	fn an_odd_margin_holds_at_exactly_half_of_it() {
		let odd = SpillPolicy {
			margin: 3,
			..policy()
		};
		let now_ms = 10_000;
		let local = Some((900, now_ms + 1_000));
		assert_eq!(
			assess(&odd, local, &[peer(898, now_ms)], now_ms).0,
			Trend::Hold,
			"gap 2 ≥ 1.5"
		);
		assert_eq!(
			assess(&odd, local, &[peer(899, now_ms)], now_ms).0,
			Trend::Decay,
			"gap 1 < 1.5"
		);
	}

	#[test]
	fn stale_reports_and_unknown_local_load_stop_spilling_at_once() {
		let fo = spill_failover(&[("10.0.0.1", 1)], policy());
		let spill = fo.spill.as_ref().unwrap();
		let admitted = run(spill, 900, &[peer(200, 0)], S, 4).unwrap();
		let now = 5 * S;
		let now_ms = now / 1_000_000;
		assert!(
			admitted.until_ms <= now_ms + 1_000,
			"expires with the local sample"
		);

		let stale = PeerView {
			report_until_ms: now_ms,
			..peer(200, 0)
		};
		assert_eq!(
			control(spill, Some((900, now_ms + 1_000)), &[stale], now + S / 4),
			None
		);
		run(spill, 900, &[peer(200, 0)], now + S / 2, 0).unwrap();
		assert_eq!(
			control(spill, None, &[peer(200, now_ms)], now + S),
			None,
			"local unknown"
		);

		// A stalled controller: the last admission expires by itself.
		let last = run(spill, 900, &[peer(200, 0)], 7 * S, 0).unwrap();
		assert!(spill.state.admission(last.until_ms - 1).is_some());
		assert_eq!(spill.state.admission(last.until_ms), None);
	}

	#[test]
	fn cooling_unmeasured_and_distant_peers_are_not_targets() {
		let near_only = SpillPolicy {
			max_peer_rtt: Some(Duration::from_millis(20)),
			..policy()
		};
		let fo = spill_failover(
			&[("10.0.0.1", 1), ("10.0.0.2", 1), ("10.0.0.3", 1)],
			near_only,
		);
		let spill = fo.spill.as_ref().unwrap();
		let far = PeerView {
			rtt: Some(Duration::from_millis(80)),
			..peer(100, 0)
		};
		let unmeasured = PeerView {
			rtt: None,
			..peer(100, 0)
		};
		let near = peer(400, 0);
		assert_eq!(
			run(spill, 900, &[far, unmeasured, near], S, 2)
				.unwrap()
				.target,
			2
		);
		let cooling = PeerView {
			cooling: true,
			..near
		};
		assert_eq!(run(spill, 900, &[far, unmeasured, cooling], 5 * S, 0), None);
	}

	#[test]
	fn two_nodes_with_delayed_reports_do_not_settle_into_spilling_to_each_other() {
		let a = spill_failover(&[("10.0.0.2", 1)], policy());
		let b = spill_failover(&[("10.0.0.1", 1)], policy());
		let (sa, sb) = (a.spill.as_ref().unwrap(), b.spill.as_ref().unwrap());
		// Each node's load moves with the share it spills or receives; reports lag one pass.
		let (base_a, base_b) = (950.0, 600.0);
		let (mut load_a, mut load_b) = (base_a, base_b);
		let mut both_admitting = 0;
		for i in 1..=120u64 {
			let now = i * S;
			let now_ms = now / 1_000_000;
			let (report_a, report_b) = (load_a as u32, load_b as u32);
			let adm_a = control(
				sa,
				Some((load_a as u32, now_ms + 1_000)),
				&[peer(report_b, now_ms)],
				now,
			);
			let adm_b = control(
				sb,
				Some((load_b as u32, now_ms + 1_000)),
				&[peer(report_a, now_ms)],
				now,
			);
			let fa = adm_a.map_or(0.0, |a| a.fraction as f64 / 1000.0);
			let fb = adm_b.map_or(0.0, |a| a.fraction as f64 / 1000.0);
			if fa > 0.0 && fb > 0.0 {
				both_admitting += 1;
			}
			// Half of a spilled share's load moves to the other node.
			load_a = base_a - 350.0 * fa + 350.0 * fb;
			load_b = base_b + 350.0 * fa - 350.0 * fb;
		}
		assert_eq!(both_admitting, 0);
		assert!(
			load_a > load_b,
			"A stays the busier one, so B never spills back"
		);
		let fa = sa.state.controller().fraction;
		assert!(fa > 0.0 && fa <= 500.0);
	}

	#[test]
	fn admission_round_trips_and_spill_target_follows_the_fraction() {
		let a = Admission {
			fraction: 1000,
			target: 0xFFFF,
			until_ms: (1 << 38) - 1,
		};
		assert_eq!(Admission::unpack(a.pack()), Some(a));
		assert_eq!(Admission::unpack(0), None);

		let fo = spill_failover(&[("10.0.0.1", 1), ("10.0.0.2", 1)], policy());
		let spill = fo.spill.as_ref().unwrap();
		let client = |port: u16| SocketAddr::new("198.51.100.7".parse().unwrap(), port);
		assert_eq!(fo.spill_target(client(1)), None, "nothing admitted");

		let until_ms = now_ns() / 1_000_000 + 60_000;
		spill.state.admission.store(
			Admission {
				fraction: 300,
				target: 1,
				until_ms,
			}
			.pack(),
			Ordering::Relaxed,
		);
		let spilled = (0..10_000u16)
			.filter(|p| fo.spill_target(client(*p)).is_some())
			.count();
		assert!(
			(2_600..3_400).contains(&spilled),
			"about 30 %, got {spilled}"
		);
		assert!((0..10_000u16).all(|p| fo.spill_target(client(p)).is_none_or(|t| t == 1)));

		fo.peers[1].record_failure(PeerFailureKind::Refused, 60 * S, 60 * S, now_ns());
		assert!(
			(0..1_000u16).all(|p| fo.spill_target(client(p)).is_none()),
			"target cooling"
		);
	}

	#[test]
	fn ingress_connections_never_spill_and_drain_or_down_forward_everything() {
		let never = || -> Option<usize> { panic!("spill consulted") };
		assert_eq!(decide(true, false, false, false, never), Decision::Local);
		assert_eq!(decide(true, false, true, false, never), Decision::Refuse);
		assert_eq!(decide(true, false, false, true, never), Decision::Refuse);
		assert_eq!(
			decide(false, false, true, true, never),
			Decision::Forward(ForwardMode::Down),
			"down wins over drain: nothing to fall back to"
		);
		assert_eq!(
			decide(false, false, false, true, never),
			Decision::Forward(ForwardMode::Drain)
		);
		assert_eq!(
			decide(false, true, true, true, never),
			Decision::Local,
			"suspended"
		);
		assert_eq!(
			decide(false, false, false, false, || Some(2)),
			Decision::Forward(ForwardMode::Spill(2))
		);
		assert_eq!(decide(false, false, false, false, || None), Decision::Local);
	}

	#[test]
	fn drain_skips_cooling_peers_while_down_still_tries_the_earliest() {
		let fo = failover(&[("10.0.0.1", 1), ("10.0.0.2", 1)]);
		fo.peers[0].record_failure(PeerFailureKind::Refused, 50, 50, 100);
		fo.peers[1].record_failure(PeerFailureKind::Refused, 20, 20, 100);
		assert!(fo.candidates_for(ForwardMode::Drain, 101).is_empty());
		assert_eq!(fo.candidates_for(ForwardMode::Spill(1), 101).len(), 0);
		let down = fo.candidates_for(ForwardMode::Down, 101);
		assert_eq!(down.len(), 1);
		assert_eq!(down[0].addr.ip().to_string(), "10.0.0.2");
		assert_eq!(fo.candidates_for(ForwardMode::Drain, 200).len(), 2);
	}

	#[test]
	fn spill_state_carries_over_only_under_the_same_policy_and_peers() {
		let peers = [("10.0.0.1", 1), ("10.0.0.2", 1)];
		let old = spill_failover(&peers, policy());
		let carry = |peers: &[(&str, u16)], spill: SpillPolicy, same_load_source: bool| {
			let mut p = spec(peers).parse().unwrap();
			p.spill = Some(spill);
			let new = Failover::new(p, Some(&old), None, same_load_source);
			Arc::ptr_eq(
				&new.spill.as_ref().unwrap().state,
				&old.spill.as_ref().unwrap().state,
			)
		};
		assert!(carry(&peers, policy(), true));
		assert!(
			!carry(&peers, policy(), false),
			"other workers behind the route"
		);
		assert!(
			!carry(&[("10.0.0.2", 1), ("10.0.0.1", 1)], policy(), true),
			"reordered peers"
		);
		assert!(!carry(
			&peers,
			SpillPolicy {
				max_fraction: 300,
				..policy()
			},
			true
		));
	}

	#[test]
	fn peer_reports_and_rtt_are_kept_per_route_peer() {
		let fo = failover(&[("10.0.0.1", 1)]);
		let p = &fo.peers[0];
		assert_eq!(p.report(), None);
		p.set_report(Some(1500), 42);
		assert_eq!(p.report(), Some((1000, 42)));
		p.set_report(None, 43);
		assert_eq!(p.report(), None, "unavailable is no report");
		assert_eq!(p.rtt(), None);
		p.record_rtt(Duration::from_millis(4));
		p.record_rtt(Duration::from_millis(8));
		assert_eq!(p.rtt(), Some(Duration::from_millis(5)));
	}

	/// The per-connection cost the spill decision adds:
	/// `cargo test --release --lib -- --ignored spill_decision_cost --nocapture`.
	#[test]
	#[ignore]
	fn spill_decision_cost() {
		use std::hint::black_box;
		const N: u32 = 20_000_000;
		let time = |label: &str, fo: &Failover| {
			let started = std::time::Instant::now();
			let mut spilled = 0u32;
			for port in 0..N {
				let client = SocketAddr::new("198.51.100.7".parse().unwrap(), port as u16);
				let decision = decide(false, false, false, black_box(fo).drain, || {
					black_box(fo).spill_target(black_box(client))
				});
				spilled += u32::from(decision != Decision::Local);
			}
			let ns = started.elapsed().as_nanos() as f64 / N as f64;
			println!("{label}: {ns:.1} ns/connection ({spilled} spilled)");
		};
		let plain = failover(&[("10.0.0.1", 1)]);
		time("failover without spill", &plain);
		let idle = spill_failover(&[("10.0.0.1", 1)], policy());
		time("spill, nothing admitted", &idle);
		let busy = spill_failover(&[("10.0.0.1", 1)], policy());
		busy.spill.as_ref().unwrap().state.admission.store(
			Admission {
				fraction: 300,
				target: 0,
				until_ms: now_ns() / 1_000_000 + 3_600_000,
			}
			.pack(),
			Ordering::Relaxed,
		);
		time("spill, 30 % admitted", &busy);
	}
}
