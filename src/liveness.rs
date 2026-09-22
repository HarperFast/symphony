//! Dead-peer detection for proxied connections (issue #45).
//!
//! * **TCP keepalive.** The `net.ipv4.tcp_keepalive_*` sysctls govern only sockets that set
//!   `SO_KEEPALIVE`, which is off by default — so without this a peer that disappears without a
//!   FIN is indistinguishable from an idle subscriber for the life of the process.
//! * **A bound on the half-closed state.** `copy_bidirectional` returns only once *both*
//!   directions have finished. After an upstream EOF the client socket sits in FIN-WAIT-2
//!   waiting for a FIN that may never come, and because its fd stays open the socket is not
//!   orphaned, so `tcp_fin_timeout` does not apply either.

use crate::metrics::ListenerMetrics;
use crate::protection::now_ns;
use socket2::{SockRef, TcpKeepalive};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Notify;

/// Probe schedule for accepted sockets. A peer is declared dead `idle + interval × retries`
/// after the last activity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeepaliveConfig {
	pub idle: Duration,
	pub interval: Duration,
	pub retries: u32,
}

/// Arm keepalive on a *listening* socket. Linux copies `SOCK_KEEPOPEN` and the per-socket
/// keepalive timings into each accepted socket and arms its timer there
/// (`tcp_create_openreq_child`), so configuring the listener once per worker covers every
/// connection it ever accepts without adding `setsockopt` calls to the accept path.
///
/// A platform that rejects the options gets a warning and no keepalive rather than a failed
/// `start()`: refusing to serve traffic is the worse failure, and this runs once per listening
/// socket, so it cannot flood the log.
pub fn arm_keepalive(socket: &impl std::os::fd::AsFd, cfg: &KeepaliveConfig, addr: &std::net::SocketAddr) {
	let params = TcpKeepalive::new()
		.with_time(cfg.idle)
		.with_interval(cfg.interval)
		.with_retries(cfg.retries);
	if let Err(e) = SockRef::from(socket).set_tcp_keepalive(&params) {
		tracing::warn!(
			"could not enable TCP keepalive on {addr}: {e}; dead peers on this listener will not be detected"
		);
	}
}

/// Nothing to do: the accepted socket already carries the listener's schedule.
#[cfg(target_os = "linux")]
pub fn arm_accepted(_stream: &tokio::net::TcpStream, _cfg: &KeepaliveConfig) {}

/// BSD-derived stacks copy `SO_KEEPALIVE` from the listener but initialise the accepted socket's
/// timers from the system-wide values, so the configured schedule has to be set here or the
/// connection quietly falls back to the host default (two hours on macOS).
/// Silent on failure: this runs per connection, and `arm_keepalive` on the listening socket has
/// already warned once if the platform rejects these options.
#[cfg(not(target_os = "linux"))]
pub fn arm_accepted(stream: &tokio::net::TcpStream, cfg: &KeepaliveConfig) {
	let params = TcpKeepalive::new()
		.with_time(cfg.idle)
		.with_interval(cfg.interval)
		.with_retries(cfg.retries);
	let _ = SockRef::from(stream).set_tcp_keepalive(&params);
}

/// The bounded half-closed state of one proxied connection. Lives on the connection task's stack
/// and is borrowed by both stream halves, so an ordinary session adds no allocation.
///
/// Armed by the *upstream* half reaching EOF, which is the terminal shape: the copy shuts down
/// the write half to the client as soon as that EOF is processed, so nothing more can be sent
/// there and no response exists that a deadline could truncate. A *client*-half EOF is
/// deliberately not armed — there the surviving direction carries the upstream's response, which
/// may legitimately be quiet for a long time before its first byte.
///
/// Both atomics are `Relaxed`: the two stream halves and the watchdog live in the same connection
/// task, so they exist to share `&self`, not to order across threads.
pub struct HalfCloseWatch<'m> {
	armed: AtomicBool,
	last_activity_ns: AtomicU64,
	notify: Notify,
	metrics: &'m ListenerMetrics,
}

impl<'m> HalfCloseWatch<'m> {
	pub fn new(metrics: &'m ListenerMetrics) -> Self {
		Self {
			armed: AtomicBool::new(false),
			last_activity_ns: AtomicU64::new(0),
			notify: Notify::new(),
			metrics,
		}
	}

	fn arm(&self) {
		self.last_activity_ns.store(now_ns(), Ordering::Relaxed);
		if !self.armed.swap(true, Ordering::Relaxed) {
			self.metrics.inc_half_closed();
			self.notify.notify_one();
		}
	}

	fn record_activity(&self) {
		if self.armed.load(Ordering::Relaxed) {
			self.last_activity_ns.store(now_ns(), Ordering::Relaxed);
		}
	}

	/// Resolves once the connection has been half-closed and the surviving direction has carried
	/// nothing for `window`. An ordinary connection arms no timer at all: this parks on a
	/// `Notify`, whose stored permit also means an EOF seen before the first poll is not lost.
	pub async fn expired(&self, window: Duration) {
		self.notify.notified().await;
		loop {
			let quiet_for =
				Duration::from_nanos(now_ns().saturating_sub(self.last_activity_ns.load(Ordering::Relaxed)));
			match window.checked_sub(quiet_for) {
				Some(remaining) if !remaining.is_zero() => tokio::time::sleep(remaining).await,
				_ => return,
			}
		}
	}
}

impl Drop for HalfCloseWatch<'_> {
	fn drop(&mut self) {
		if *self.armed.get_mut() {
			self.metrics.dec_half_closed();
		}
	}
}

/// Reports a stream's reads to the connection's [`HalfCloseWatch`]. Writes pass straight through:
/// every byte written to one half was read from the other, so reads alone see all activity.
pub struct Watched<'w, S> {
	inner: S,
	watch: &'w HalfCloseWatch<'w>,
	arms_on_eof: bool,
}

impl<'w, S> Watched<'w, S> {
	/// The upstream half, whose EOF puts the connection into the bounded half-closed state.
	pub fn upstream(inner: S, watch: &'w HalfCloseWatch<'w>) -> Self {
		Self { inner, watch, arms_on_eof: true }
	}

	/// The client half, whose reads are the activity that keeps a half-closed connection alive.
	pub fn client(inner: S, watch: &'w HalfCloseWatch<'w>) -> Self {
		Self { inner, watch, arms_on_eof: false }
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for Watched<'_, S> {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
		let this = self.get_mut();
		let before = buf.filled().len();
		let result = Pin::new(&mut this.inner).poll_read(cx, buf);
		if matches!(result, Poll::Ready(Ok(()))) {
			if buf.filled().len() > before {
				this.watch.record_activity();
			} else if this.arms_on_eof {
				this.watch.arm();
			}
		}
		result
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Watched<'_, S> {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
		Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
	}

	fn poll_write_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &[std::io::IoSlice<'_>],
	) -> Poll<std::io::Result<usize>> {
		Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
	}

	fn is_write_vectored(&self) -> bool {
		self.inner.is_write_vectored()
	}

	fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.get_mut().inner).poll_flush(cx)
	}

	fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
		Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::io;
	use tokio::net::{TcpListener, TcpStream};

	fn config() -> KeepaliveConfig {
		KeepaliveConfig { idle: Duration::from_secs(97), interval: Duration::from_secs(13), retries: 4 }
	}

	/// The invariant the accept path depends on, asserted where it is actually observable. On
	/// Linux `arm_accepted` is a no-op, so this fails if the kernel ever stops copying the
	/// listener's schedule into accepted sockets — which would silently cost every proxied
	/// connection its dead-peer detection without changing anything a round-trip test can see.
	#[tokio::test]
	async fn accepted_sockets_carry_the_configured_keepalive() {
		let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.local_addr().unwrap();
		arm_keepalive(&listener, &config(), &addr);

		let client = TcpStream::connect(addr).await.unwrap();
		let (accepted, _) = listener.accept().await.unwrap();
		arm_accepted(&accepted, &config());

		let sock = SockRef::from(&accepted);
		assert!(sock.keepalive().unwrap(), "SO_KEEPALIVE must reach the accepted socket");
		assert_eq!(sock.keepalive_time().unwrap(), Duration::from_secs(97));
		assert_eq!(sock.keepalive_interval().unwrap(), Duration::from_secs(13));
		assert_eq!(sock.keepalive_retries().unwrap(), 4);
		drop(client);
	}

	/// A stream that yields `chunks` reads of one byte each and then EOFs forever.
	struct Chunks {
		remaining: usize,
	}

	impl AsyncRead for Chunks {
		fn poll_read(
			mut self: Pin<&mut Self>,
			_cx: &mut Context<'_>,
			buf: &mut ReadBuf<'_>,
		) -> Poll<io::Result<()>> {
			if self.remaining > 0 {
				self.remaining -= 1;
				buf.put_slice(b"x");
			}
			Poll::Ready(Ok(()))
		}
	}

	async fn drain<S: AsyncRead + Unpin>(stream: &mut S) {
		use tokio::io::AsyncReadExt;
		let mut buf = [0u8; 8];
		while stream.read(&mut buf).await.unwrap() > 0 {}
	}

	#[tokio::test(start_paused = true)]
	async fn an_unarmed_connection_never_expires() {
		let metrics = ListenerMetrics::default();
		let watch = HalfCloseWatch::new(&metrics);
		// The client half reaching EOF is the request/response half-close, not the bounded state.
		let mut client = Watched::client(Chunks { remaining: 2 }, &watch);
		drain(&mut client).await;

		assert!(
			tokio::time::timeout(Duration::from_secs(3600), watch.expired(Duration::from_secs(60)))
				.await
				.is_err(),
			"a client-side EOF must not arm the half-close bound"
		);
		assert_eq!(watch.metrics.half_closed_connections.load(Ordering::Relaxed), 0);
	}

	// The two tests below run on the real clock: the activity stamp comes from `now_ns()`, a
	// `std::time::Instant` offset, which a paused tokio clock does not move — so a paused run
	// would loop forever rather than measure the deadline. Windows are milliseconds to keep the
	// suite fast, with the assertions a window either side of each boundary.

	#[tokio::test]
	async fn an_upstream_eof_expires_after_a_quiet_window() {
		let metrics = ListenerMetrics::default();
		let watch = HalfCloseWatch::new(&metrics);
		let mut upstream = Watched::upstream(Chunks { remaining: 0 }, &watch);
		drain(&mut upstream).await;

		assert_eq!(watch.metrics.half_closed_connections.load(Ordering::Relaxed), 1);
		tokio::time::timeout(Duration::from_secs(5), watch.expired(Duration::from_millis(100)))
			.await
			.expect("the bound must fire once the surviving direction goes quiet");
	}

	#[tokio::test]
	async fn activity_on_the_surviving_direction_defers_expiry() {
		let metrics = ListenerMetrics::default();
		let watch = HalfCloseWatch::new(&metrics);
		let mut upstream = Watched::upstream(Chunks { remaining: 0 }, &watch);
		drain(&mut upstream).await;

		let expired = watch.expired(Duration::from_millis(300));
		tokio::pin!(expired);

		// One byte on the surviving direction 200ms in, restamping the activity clock.
		let mut client = Watched::client(Chunks { remaining: 1 }, &watch);
		tokio::time::sleep(Duration::from_millis(200)).await;
		drain(&mut client).await;

		// Without the reset the bound would have fired at t=300ms; the new deadline is t=500ms.
		assert!(
			tokio::time::timeout(Duration::from_millis(200), &mut expired).await.is_err(),
			"activity must push the deadline out, not be ignored"
		);
		assert!(
			tokio::time::timeout(Duration::from_secs(5), &mut expired).await.is_ok(),
			"expiry is deferred, not cancelled"
		);
	}

	/// The gauge is a gauge: it must come back down however the connection ended.
	#[tokio::test]
	async fn the_gauge_returns_to_zero_when_the_connection_drops() {
		let metrics = ListenerMetrics::default();
		{
			let watch = HalfCloseWatch::new(&metrics);
			let mut upstream = Watched::upstream(Chunks { remaining: 0 }, &watch);
			drain(&mut upstream).await;
			assert_eq!(metrics.half_closed_connections.load(Ordering::Relaxed), 1);
		}
		assert_eq!(metrics.half_closed_connections.load(Ordering::Relaxed), 0);
	}
}
