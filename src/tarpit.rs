use crate::metrics::{GlobalMetrics, ListenerMetrics};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, Interest};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio::time::Instant;

/// Bounds the reads a client that keeps writing can cost its hold.
const DISCARD_BUDGET: usize = 64 * 1024;

/// How soon a client past `DISCARD_BUDGET` is seen to have closed.
const CLOSE_CHECK_INTERVAL: Duration = Duration::from_secs(1);

/// A hold longer than any client's connect timeout only holds a socket its client has abandoned.
const MAX_FAILURE_HOLD_MS: f64 = 600_000.0;

const DEFAULT_FAILURE_HOLD_JITTER: f64 = 0.5;

/// How long a client whose certificate is rejected is held: `hold` scaled by a uniform draw from
/// `[1 - jitter, 1 + jitter]`, so clients rejected together (a restart, a traffic shift) do not all
/// come back together.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct FailureHold {
	pub hold: Duration,
	pub jitter: f64,
}

impl FailureHold {
	pub const OFF: Self = Self {
		hold: Duration::ZERO,
		jitter: 0.0,
	};

	/// `failureHoldMs` (whole ms; zero, unset or under 1 ms keeps today's alert) and
	/// `failureHoldJitter`.
	pub fn parse(hold_ms: Option<f64>, jitter: Option<f64>) -> Result<Self, String> {
		let jitter = match jitter {
			None => DEFAULT_FAILURE_HOLD_JITTER,
			Some(j) if (0.0..=1.0).contains(&j) => j,
			Some(j) => return Err(format!("mtls.failureHoldJitter must be in [0, 1], got {j}")),
		};
		match hold_ms {
			Some(ms) if !(0.0..=MAX_FAILURE_HOLD_MS).contains(&ms) => Err(format!(
				"mtls.failureHoldMs must be a number of ms in [0, {MAX_FAILURE_HOLD_MS}], got {ms}"
			)),
			Some(ms) if ms >= 1.0 => Ok(Self {
				hold: Duration::from_millis(ms as u64),
				jitter,
			}),
			_ => Ok(Self::OFF),
		}
	}

	pub fn is_off(&self) -> bool {
		self.hold.is_zero()
	}

	pub fn draw(&self) -> Duration {
		self.scaled(random_unit())
	}

	/// `unit` is in `[0, 1)`.
	fn scaled(&self, unit: f64) -> Duration {
		self.hold
			.mul_f64(1.0 - self.jitter + 2.0 * self.jitter * unit)
	}
}

fn random_unit() -> f64 {
	ring::rand::generate::<[u8; 8]>(&ring::rand::SystemRandom::new())
		.map(|bytes| (u64::from_le_bytes(bytes.expose()) >> 11) as f64 / (1u64 << 53) as f64)
		.unwrap_or(0.5)
}

/// The listener default for `maxHeldConnections`.
const DEFAULT_MAX_HELD_CONNECTIONS: u32 = 10_000;

/// The default leaves at least half of every listener's `maxConnections` to connections that are
/// not held: each accept gate compares the proxy-wide active count, held sockets included, with its
/// own limit, so the smallest limit is the one holds can exhaust.
pub fn default_max_held(max_connections: impl IntoIterator<Item = u32>) -> u32 {
	max_connections
		.into_iter()
		.filter(|&limit| limit > 0)
		.min()
		.map_or(DEFAULT_MAX_HELD_CONNECTIONS, |limit| {
			DEFAULT_MAX_HELD_CONNECTIONS.min(limit / 2)
		})
}

/// A held connection, counted proxy-wide (what `maxHeldConnections` caps) and on its listener's
/// gauge until dropped.
pub struct HeldSlot {
	global: Arc<GlobalMetrics>,
	listener: Arc<ListenerMetrics>,
}

impl HeldSlot {
	/// `None` once `cap` connections are held across the proxy. A lowered cap applies to new
	/// acquisitions only.
	pub fn acquire(
		global: &Arc<GlobalMetrics>,
		listener: &Arc<ListenerMetrics>,
		cap: u32,
	) -> Option<Self> {
		global
			.held_connections
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |held| {
				(held < u64::from(cap)).then_some(held + 1)
			})
			.ok()?;
		listener.held_connections.fetch_add(1, Ordering::Relaxed);
		Some(Self {
			global: global.clone(),
			listener: listener.clone(),
		})
	}
}

impl Drop for HeldSlot {
	fn drop(&mut self) {
		self.global.held_connections.fetch_sub(1, Ordering::Relaxed);
		self.listener
			.held_connections
			.fetch_sub(1, Ordering::Relaxed);
	}
}

/// Hold `client` without writing to it until `deadline`, until it closes or errors, or until the
/// proxy stops (`stop`'s sender is dropped), then close it. What it sends is read and discarded,
/// up to `DISCARD_BUDGET`.
pub async fn hold_silently(
	mut client: TcpStream,
	deadline: Instant,
	mut stop: watch::Receiver<()>,
) {
	let until_closed = async {
		{
			let mut sink = [0u8; 512];
			let mut left = DISCARD_BUDGET;
			while left > 0 {
				match client.read(&mut sink).await {
					Ok(0) | Err(_) => return,
					Ok(n) => left = left.saturating_sub(n),
				}
			}
		}
		// The bytes now stay unread, and a close behind them shows only in the reactor's readiness.
		loop {
			tokio::time::sleep(CLOSE_CHECK_INTERVAL).await;
			if crate::upstream::read_closed(client.ready(Interest::READABLE)) {
				return;
			}
		}
	};
	tokio::select! {
		_ = until_closed => {}
		_ = tokio::time::sleep_until(deadline) => {}
		_ = stop.changed() => {}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::time::Duration;
	use tokio::io::AsyncWriteExt;
	use tokio::net::TcpListener;

	async fn pair() -> (TcpStream, TcpStream) {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let client = TcpStream::connect(listener.local_addr().unwrap())
			.await
			.unwrap();
		let (server, _) = listener.accept().await.unwrap();
		(client, server)
	}

	/// Reads until EOF or reset, returning how many bytes arrived and when the stream ended.
	async fn drain(client: &mut TcpStream) -> (usize, Instant) {
		let mut got = 0;
		let mut buf = [0u8; 1024];
		loop {
			match client.read(&mut buf).await {
				Ok(0) | Err(_) => return (got, Instant::now()),
				Ok(n) => got += n,
			}
		}
	}

	#[tokio::test]
	async fn holds_silently_until_the_deadline_then_closes() {
		let (mut client, server) = pair().await;
		let (_stop_tx, stop) = watch::channel(());
		let start = Instant::now();
		let hold = tokio::spawn(hold_silently(
			server,
			start + Duration::from_millis(300),
			stop,
		));
		client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
		let (got, ended) = drain(&mut client).await;
		assert_eq!(got, 0, "a held client must receive nothing");
		assert!(ended - start >= Duration::from_millis(290));
		hold.await.unwrap();
	}

	#[tokio::test]
	async fn a_client_that_closes_ends_its_hold() {
		let (client, server) = pair().await;
		let (_stop_tx, stop) = watch::channel(());
		let start = Instant::now();
		let hold = tokio::spawn(hold_silently(server, start + Duration::from_secs(30), stop));
		drop(client);
		tokio::time::timeout(Duration::from_secs(5), hold)
			.await
			.expect("the hold must end when its client closes")
			.unwrap();
	}

	#[tokio::test]
	async fn stopping_the_proxy_ends_every_hold_even_one_started_after() {
		let (mut early_client, early_server) = pair().await;
		let (stop_tx, stop) = watch::channel(());
		let deadline = Instant::now() + Duration::from_secs(30);
		let early = tokio::spawn(hold_silently(early_server, deadline, stop.clone()));
		drop(stop_tx);
		let (mut late_client, late_server) = pair().await;
		let late = tokio::spawn(hold_silently(late_server, deadline, stop));
		for (hold, client) in [(early, &mut early_client), (late, &mut late_client)] {
			tokio::time::timeout(Duration::from_secs(5), hold)
				.await
				.expect("a stopped proxy must release its holds")
				.unwrap();
			assert_eq!(drain(client).await.0, 0);
		}
	}

	#[tokio::test]
	async fn past_the_discard_budget_the_hold_keeps_waiting_without_reading() {
		let (mut client, server) = pair().await;
		let (_stop_tx, stop) = watch::channel(());
		let start = Instant::now();
		let hold = tokio::spawn(hold_silently(
			server,
			start + Duration::from_millis(400),
			stop,
		));
		let flood = vec![0u8; DISCARD_BUDGET + 4096];
		client.write_all(&flood).await.unwrap();
		let (got, ended) = drain(&mut client).await;
		assert_eq!(got, 0);
		assert!(
			ended - start >= Duration::from_millis(390),
			"exceeding the budget must not end the hold early"
		);
		hold.await.unwrap();
	}

	#[tokio::test]
	async fn a_client_past_the_discard_budget_that_closes_ends_its_hold() {
		let (mut client, server) = pair().await;
		let (_stop_tx, stop) = watch::channel(());
		let hold = tokio::spawn(hold_silently(
			server,
			Instant::now() + Duration::from_secs(30),
			stop,
		));
		client
			.write_all(&vec![0u8; DISCARD_BUDGET + 4096])
			.await
			.unwrap();
		tokio::time::sleep(Duration::from_millis(100)).await;
		drop(client);
		tokio::time::timeout(CLOSE_CHECK_INTERVAL * 3, hold)
			.await
			.expect("the hold must end once its client closes, read or not")
			.unwrap();
	}

	#[test]
	fn the_hold_is_drawn_from_its_jitter_range() {
		let hold = FailureHold {
			hold: Duration::from_secs(10),
			jitter: 0.5,
		};
		assert_eq!(hold.scaled(0.0), Duration::from_secs(5));
		assert_eq!(hold.scaled(0.5), Duration::from_secs(10));
		assert!(hold.scaled(0.999_999) < Duration::from_secs(15));
		let draws: Vec<_> = (0..64).map(|_| hold.draw()).collect();
		assert!(draws
			.iter()
			.all(|d| (Duration::from_secs(5)..Duration::from_secs(15)).contains(d)));
		assert!(
			draws.iter().any(|d| *d != draws[0]),
			"draws must differ, or clients come back together"
		);
		let fixed = FailureHold {
			jitter: 0.0,
			..hold
		};
		assert!((0..16).all(|_| fixed.draw() == Duration::from_secs(10)));
	}

	#[test]
	fn failure_hold_settings_are_validated() {
		assert_eq!(FailureHold::parse(None, None), Ok(FailureHold::OFF));
		assert_eq!(FailureHold::parse(Some(0.5), None), Ok(FailureHold::OFF));
		assert_eq!(
			FailureHold::parse(Some(5000.0), None),
			Ok(FailureHold {
				hold: Duration::from_secs(5),
				jitter: DEFAULT_FAILURE_HOLD_JITTER
			})
		);
		assert_eq!(
			FailureHold::parse(Some(5000.0), Some(0.0)).unwrap().jitter,
			0.0
		);
		for (hold, jitter) in [
			(Some(-1.0), None),
			(Some(MAX_FAILURE_HOLD_MS + 1.0), None),
			(Some(f64::NAN), None),
			(Some(f64::INFINITY), None),
			(Some(5000.0), Some(1.5)),
			(Some(5000.0), Some(-0.1)),
			(Some(5000.0), Some(f64::NAN)),
		] {
			assert!(
				FailureHold::parse(hold, jitter).is_err(),
				"{hold:?} {jitter:?}"
			);
		}
	}

	#[test]
	fn the_cap_bounds_slots_across_listeners_and_drop_releases_them() {
		let global = Arc::new(GlobalMetrics::default());
		let (a, b) = (
			Arc::new(ListenerMetrics::default()),
			Arc::new(ListenerMetrics::default()),
		);
		let held = |m: &ListenerMetrics| m.held_connections.load(Ordering::Relaxed);
		let mut slots: Vec<_> = (0..2)
			.filter_map(|_| HeldSlot::acquire(&global, &a, 3))
			.collect();
		slots.extend((0..2).filter_map(|_| HeldSlot::acquire(&global, &b, 3)));
		assert_eq!(
			slots.len(),
			3,
			"the cap counts the whole proxy, as maxConnections does"
		);
		assert_eq!((held(&a), held(&b)), (2, 1));
		assert!(HeldSlot::acquire(&global, &a, 0).is_none());
		assert_eq!(held(&a), 2, "a refused slot leaves the gauge alone");
		drop(slots);
		assert_eq!(global.held_connections.load(Ordering::Relaxed), 0);
		assert_eq!((held(&a), held(&b)), (0, 0));
		assert!(HeldSlot::acquire(&global, &b, 1).is_some());
	}

	#[test]
	fn racing_acquisitions_never_exceed_the_cap() {
		let global = Arc::new(GlobalMetrics::default());
		let metrics = Arc::new(ListenerMetrics::default());
		let taken = std::sync::atomic::AtomicU32::new(0);
		std::thread::scope(|scope| {
			for _ in 0..8 {
				scope.spawn(|| {
					for _ in 0..1000 {
						if let Some(slot) = HeldSlot::acquire(&global, &metrics, 4) {
							let now = taken.fetch_add(1, Ordering::SeqCst) + 1;
							assert!(now <= 4, "{now} slots held under a cap of 4");
							taken.fetch_sub(1, Ordering::SeqCst);
							drop(slot);
						}
					}
				});
			}
		});
		assert_eq!(metrics.held_connections.load(Ordering::Relaxed), 0);
		assert_eq!(global.held_connections.load(Ordering::Relaxed), 0);
	}

	#[test]
	fn the_default_cap_leaves_half_of_max_connections() {
		assert_eq!(default_max_held([0]), DEFAULT_MAX_HELD_CONNECTIONS);
		assert_eq!(default_max_held([500]), 250);
		assert_eq!(default_max_held([1_000_000]), DEFAULT_MAX_HELD_CONNECTIONS);
		assert_eq!(
			default_max_held([1000, 0, 200]),
			100,
			"the smallest limit any listener's gate applies"
		);
	}
}
