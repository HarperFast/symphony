//! Peer failover: while a route's local upstream is down (or the route is draining), forward its
//! new connections, still as raw TLS, to a peer node's failover ingress listener.

use crate::balancer::SlotHealth;
use crate::metrics::{CountingStream, ErrorKind, PeerFailureKind};
use crate::protection::now_ns;
use crate::proxy_conn::{emit, forward_opaque, ConnContext, JsEvent};
use crate::router::{Destination, LiveRouteTable, RouteMetricIdentity};
use crate::sni::PeekInfo;
use napi::threadsafe_function::ThreadsafeFunction;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
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

#[derive(Clone, Debug)]
pub struct FailoverSpec {
	pub peers: Vec<(String, u16)>,
	pub drain: bool,
	pub probe_interval_ms: Option<f64>,
	pub cooldown_min_ms: Option<f64>,
	pub cooldown_max_ms: Option<f64>,
}

#[derive(Debug, PartialEq)]
pub struct FailoverPolicy {
	pub peers: Vec<SocketAddr>,
	pub drain: bool,
	pub probe_interval: Duration,
	pub cooldown_min: Duration,
	pub cooldown_max: Duration,
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
	pub forwarded: AtomicU64,
	failures: [AtomicU64; PeerFailureKind::COUNT],
}

impl FailoverPeer {
	fn new(addr: SocketAddr) -> Self {
		Self {
			addr,
			cooldown: AtomicU64::new(0),
			forwarded: AtomicU64::new(0),
			failures: std::array::from_fn(|_| AtomicU64::new(0)),
		}
	}

	fn cooldown_until(&self) -> u64 {
		self.cooldown.load(Ordering::Relaxed) & COOLDOWN_UNTIL_MASK
	}

	pub fn cooling_down(&self, now: u64) -> bool {
		now < self.cooldown_until()
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

	fn record_success(&self) {
		self.cooldown.store(0, Ordering::Relaxed);
		self.forwarded.fetch_add(1, Ordering::Relaxed);
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
}

impl Failover {
	/// `previous` is the same route's failover in the previous table, passed only when the route
	/// keeps its metric identity, so peer counters and cooldowns continue rather than reset.
	pub fn new(
		policy: FailoverPolicy,
		previous: Option<&Failover>,
		tcp_health: Option<Arc<SlotHealth>>,
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
		Self {
			drain: policy.drain,
			probe_interval: policy.probe_interval,
			cooldown_min_ns: policy.cooldown_min.as_nanos() as u64,
			cooldown_max_ns: policy.cooldown_max.as_nanos() as u64,
			peers,
			cursor: AtomicUsize::new(0),
			tcp_health,
			status: previous.map(|p| p.status.clone()).unwrap_or_default(),
		}
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

/// Forward a connection whose ClientHello has only been peeked to the route's peers. Each attempt
/// sends a PROXY v2 header and the ClientHello, then waits for the peer's first byte before
/// reading anything more from the client — so a peer that closes without answering received
/// nothing a retry could duplicate, and the hello is replayed to the next one.
pub async fn forward_to_peers(
	client: TcpStream,
	peek: &PeekInfo,
	failover: &Failover,
	peer_addr: SocketAddr,
	local_addr: Option<SocketAddr>,
	ctx: &ConnContext,
	route: &RouteMetricIdentity,
) -> Result<(), ErrorKind> {
	if !peek.complete || peek.hello_len == 0 {
		return Err(ErrorKind::UpstreamConnect);
	}
	// Every attempt shares the handshake budget the client would have had on this node.
	let deadline = Instant::now() + ctx.handshake_timeout();
	let mut client = CountingStream::new(client, &ctx.listener_metrics, Some(&route.counters));

	let mut prefix = Vec::with_capacity(28 + peek.hello_len);
	crate::upstream::write_proxy_v2_header(&mut prefix, peer_addr, local_addr, &[])
		.await
		.map_err(|_| ErrorKind::UpstreamConnect)?;
	let header_len = prefix.len();
	prefix.resize(header_len + peek.hello_len, 0);
	// The bytes are already buffered (peek saw them), so this does not wait on the client.
	match tokio::time::timeout_at(deadline, client.read_exact(&mut prefix[header_len..])).await {
		Ok(Ok(_)) => {}
		_ => return Err(ErrorKind::UpstreamConnect),
	}

	let (candidate_count, candidates) = failover.candidates(now_ns());
	for (attempt, peer) in candidates.enumerate() {
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
				peer.record_success();
				return forward_opaque(&mut client, &mut upstream, peer_addr, ctx).await;
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
	failover.status.exhausted.fetch_add(1, Ordering::Relaxed);
	Err(ErrorKind::UpstreamConnect)
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
			if now.saturating_sub(status.last_probe_ns.load(Ordering::Relaxed)) + interval / 10
				< interval
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

		let mut probes = JoinSet::new();
		for (endpoint, healths) in due {
			probes.spawn(async move {
				if probe(&endpoint).await {
					for (health, observed) in healths {
						health.clear_if_unchanged(observed);
					}
				}
			});
		}
		tokio::select! {
			_ = shutdown.recv() => {
				probes.abort_all();
				return;
			}
			_ = async { while probes.join_next().await.is_some() {} } => {}
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
		}
	}

	fn failover(peers: &[(&str, u16)]) -> Failover {
		Failover::new(spec(peers).parse().unwrap(), None, None)
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
		peer.record_success();
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
		old.peers[0].record_success();
		old.status.replays.fetch_add(3, Ordering::Relaxed);
		let new = Failover::new(
			spec(&[("10.0.0.1", 1), ("10.0.0.3", 1)]).parse().unwrap(),
			Some(&old),
			None,
		);
		assert!(Arc::ptr_eq(&new.peers[0], &old.peers[0]));
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
}
