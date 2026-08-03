use crate::protection::BlockReason;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Declares a small closed enum plus the label text each variant carries into the exported
/// metrics. `ALL` drives both the per-variant counter array and the export, so a new variant
/// is automatically counted and exported — there is no separate list to keep in sync.
macro_rules! labeled_enum {
	($name:ident { $($(#[$doc:meta])* $variant:ident => $label:literal),+ $(,)? }) => {
		#[derive(Clone, Copy, Debug, PartialEq, Eq)]
		pub enum $name {
			$($(#[$doc])* $variant),+
		}

		impl $name {
			pub const ALL: &'static [$name] = &[$($name::$variant),+];
			pub const COUNT: usize = Self::ALL.len();

			pub fn as_str(self) -> &'static str {
				match self {
					$(Self::$variant => $label),+
				}
			}
		}
	};
}

labeled_enum!(BlockKind {
	/// Listener-level `maxConnections` cap — refused in the accept loop, before protection runs.
	MaxConnections => "max_connections",
	CidrBlocked => "cidr_blocked",
	Ja3Blocked => "ja3_blocked",
	Ja4Blocked => "ja4_blocked",
	IncompleteHandshake => "incomplete_handshake",
	NoSni => "no_sni",
	RateLimited => "rate_limited",
	TooManyConnections => "too_many_connections",
	PenaltyBoxed => "penalty_boxed",
});

// Exhaustive by construction: adding a BlockReason variant fails to compile until it is given
// a BlockKind, so a new protection check can never silently land in an unlabeled bucket.
impl From<&BlockReason> for BlockKind {
	fn from(reason: &BlockReason) -> Self {
		match reason {
			BlockReason::CidrBlocked => Self::CidrBlocked,
			BlockReason::Ja3Blocked => Self::Ja3Blocked,
			BlockReason::Ja4Blocked => Self::Ja4Blocked,
			BlockReason::IncompleteHandshake => Self::IncompleteHandshake,
			BlockReason::NoSni => Self::NoSni,
			BlockReason::RateLimited => Self::RateLimited,
			BlockReason::TooManyConnections => Self::TooManyConnections,
			BlockReason::PenaltyBoxed => Self::PenaltyBoxed,
		}
	}
}

labeled_enum!(ErrorKind {
	/// SNI matched no route and the listener has no default route.
	NoRoute => "no_route",
	/// The route's own rate limiter rejected the connection.
	RouteRateLimited => "route_rate_limited",
	/// A suspended connection was never resolved — timed out or rejected by JS.
	SuspendUnresolved => "suspend_unresolved",
	/// TLS handshake failed or timed out.
	TlsHandshake => "tls_handshake",
	/// Route asks for TLS termination but has no usable cert (e.g. cert build failed).
	TlsMissingCert => "tls_missing_cert",
	/// Could not establish the upstream connection.
	UpstreamConnect => "upstream_connect",
	/// The proxied session hit `idleTimeoutMs`. Note that today this fires on *total* duration,
	/// not idleness — `forward()` wraps the copy in a hard `tokio::time::timeout` that does not
	/// reset on activity (issue #34, pre-existing). Until that is fixed this counts busy
	/// connections cut at the deadline, not quiet ones.
	IdleTimeout => "idle_timeout",
	/// I/O error while proxying an established session.
	Stream => "stream",
	/// HTTP-mode listener could not read the request head.
	HttpHeader => "http_header",
});

impl ErrorKind {
	pub fn is_route_scoped(self) -> bool {
		!matches!(self, Self::NoRoute | Self::HttpHeader)
	}
}

/// Per-listener counters. Every field is `Relaxed` — these are monotonic counters and gauges
/// read out of band by `metrics()`, never used to make a decision that needs ordering.
pub struct ListenerMetrics {
	pub active_connections: AtomicU64,
	pub total_accepted: AtomicU64,
	/// Bytes read from clients on this listener (client → upstream), counted where the proxy
	/// sees them. On a terminated-TLS route that is the plaintext stream — the handshake happens
	/// before the counter is installed and is excluded. On a passthrough route the proxy has no
	/// plaintext view and simply forwards wire bytes, so the handshake records are part of the
	/// stream and are counted.
	pub bytes_in: AtomicU64,
	/// Bytes written to clients on this listener (upstream → client). Same framing as `bytes_in`.
	pub bytes_out: AtomicU64,
	blocked_by_kind: [AtomicU64; BlockKind::COUNT],
	errors_by_kind: [AtomicU64; ErrorKind::COUNT],
}

impl Default for ListenerMetrics {
	fn default() -> Self {
		Self {
			active_connections: AtomicU64::new(0),
			total_accepted: AtomicU64::new(0),
			bytes_in: AtomicU64::new(0),
			bytes_out: AtomicU64::new(0),
			blocked_by_kind: std::array::from_fn(|_| AtomicU64::new(0)),
			errors_by_kind: std::array::from_fn(|_| AtomicU64::new(0)),
		}
	}
}

impl ListenerMetrics {
	pub fn inc_active(&self) {
		self.active_connections.fetch_add(1, Ordering::Relaxed);
		self.total_accepted.fetch_add(1, Ordering::Relaxed);
	}

	pub fn dec_active(&self) {
		self.active_connections.fetch_sub(1, Ordering::Relaxed);
	}

	pub fn inc_blocked(&self, kind: BlockKind) {
		self.blocked_by_kind[kind as usize].fetch_add(1, Ordering::Relaxed);
	}

	/// Direct byte accounting for paths that handle a whole message at once (the HTTP-mode
	/// listener), where `CountingStream`'s per-connection batching would buy nothing — these
	/// fire once or twice per connection, not per chunk.
	pub fn add_bytes_in(&self, bytes: u64) {
		self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
	}

	pub fn add_bytes_out(&self, bytes: u64) {
		self.bytes_out.fetch_add(bytes, Ordering::Relaxed);
	}

	pub fn inc_error(&self, kind: ErrorKind) {
		self.errors_by_kind[kind as usize].fetch_add(1, Ordering::Relaxed);
	}

	/// Per-reason block counts, in `BlockKind::ALL` order. Zero-valued reasons are included
	/// so an exported series exists from the first scrape rather than appearing mid-incident.
	pub fn blocked_by_reason(&self) -> Vec<(&'static str, u64)> {
		BlockKind::ALL
			.iter()
			.map(|k| (k.as_str(), self.blocked_by_kind[*k as usize].load(Ordering::Relaxed)))
			.collect()
	}

	/// Per-reason error counts, in `ErrorKind::ALL` order. See `blocked_by_reason`.
	pub fn errors_by_reason(&self) -> Vec<(&'static str, u64)> {
		ErrorKind::ALL
			.iter()
			.map(|k| (k.as_str(), self.errors_by_kind[*k as usize].load(Ordering::Relaxed)))
			.collect()
	}
}

/// Counters that begin after a configured route is selected. Pre-route blocks and errors remain
/// listener-scoped because they have no trustworthy route identity.
pub struct RouteMetrics {
	pub active_connections: AtomicU64,
	pub total_connections: AtomicU64,
	pub bytes_in: AtomicU64,
	pub bytes_out: AtomicU64,
	errors_by_kind: [AtomicU64; ErrorKind::COUNT],
}

impl Default for RouteMetrics {
	fn default() -> Self {
		Self {
			active_connections: AtomicU64::new(0),
			total_connections: AtomicU64::new(0),
			bytes_in: AtomicU64::new(0),
			bytes_out: AtomicU64::new(0),
			errors_by_kind: std::array::from_fn(|_| AtomicU64::new(0)),
		}
	}
}

impl RouteMetrics {
	fn inc_active(&self) {
		self.active_connections.fetch_add(1, Ordering::Relaxed);
		self.total_connections.fetch_add(1, Ordering::Relaxed);
	}

	fn dec_active(&self) {
		let _ = self
			.active_connections
			.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| value.checked_sub(1));
	}

	pub fn add_bytes_in(&self, bytes: u64) {
		self.bytes_in.fetch_add(bytes, Ordering::Relaxed);
	}

	pub fn inc_error(&self, kind: ErrorKind) {
		debug_assert!(kind.is_route_scoped(), "pre-route error attributed to a route");
		if kind.is_route_scoped() {
			self.errors_by_kind[kind as usize].fetch_add(1, Ordering::Relaxed);
		}
	}

	/// Route error series are sparse to keep scrape cardinality proportional to failures rather
	/// than multiplying every zero-valued reason by every configured tenant route.
	pub fn errors_by_reason(&self) -> Vec<(&'static str, u64)> {
		ErrorKind::ALL
			.iter()
			.filter(|kind| kind.is_route_scoped())
			.filter_map(|kind| {
				let count = self.errors_by_kind[*kind as usize].load(Ordering::Relaxed);
				(count > 0).then_some((kind.as_str(), count))
			})
			.collect()
	}
}

pub struct RouteActiveGuard {
	metrics: Arc<RouteMetrics>,
}

impl RouteActiveGuard {
	pub fn new(metrics: Arc<RouteMetrics>) -> Self {
		metrics.inc_active();
		Self { metrics }
	}
}

impl Drop for RouteActiveGuard {
	fn drop(&mut self) {
		self.metrics.dec_active();
	}
}

/// Sums a per-reason breakdown into its total.
///
/// The exported totals are derived from the same values the breakdown reports rather than kept
/// as separate counters. A standalone `total_blocked` incremented next to its reason counter is
/// two non-atomic writes, so a scrape landing between them observes a total that does not equal
/// the sum of its parts — the invariant would hold only while the proxy is idle, which is
/// exactly when nobody is looking. Deriving makes it structural, and removes an atomic from the
/// block/error paths.
pub fn total_of(counts: &[(&'static str, u64)]) -> u64 {
	counts.iter().map(|(_, count)| count).sum()
}

// No proxy-wide blocked counter: it is derived from the listeners in `metrics()` for the same
// reason the per-listener totals are derived from their reasons — a separately incremented copy
// can disagree with its parts under traffic.
#[derive(Default)]
pub struct GlobalMetrics {
	pub active_connections: AtomicU64,
	pub pending_suspended: AtomicU64,
	/// Suspended connections that JS resolved with a route.
	pub suspended_resolved: AtomicU64,
	/// Suspended connections that timed out or were rejected with a null route.
	pub suspended_unresolved: AtomicU64,
}

impl GlobalMetrics {
	pub fn inc_active(&self) {
		self.active_connections.fetch_add(1, Ordering::Relaxed);
	}

	pub fn dec_active(&self) {
		self.active_connections.fetch_sub(1, Ordering::Relaxed);
	}

	pub fn inc_suspended(&self) {
		self.pending_suspended.fetch_add(1, Ordering::Relaxed);
	}

	/// Leave the pending gauge, recording how the suspension ended.
	pub fn dec_suspended(&self, resolved: bool) {
		self.pending_suspended.fetch_sub(1, Ordering::Relaxed);
		if resolved {
			self.suspended_resolved.fetch_add(1, Ordering::Relaxed);
		} else {
			self.suspended_unresolved.fetch_add(1, Ordering::Relaxed);
		}
	}
}

/// Bytes a connection may accumulate locally before publishing to the shared listener counters.
/// The whole point of the local buffer is to keep the shared cache line off the per-chunk path
/// (see `CountingStream`), so this wants to be well above the per-direction copy buffer
/// (`DEFAULT_COPY_BUFFER_SIZE`, 8 KiB) — at 256 KiB a saturated connection publishes ~32× less
/// often than it would per chunk, while a scrape still sees a busy connection's traffic within a
/// fraction of a second. A smaller configured buffer only means more chunks per flush.
const COUNTER_FLUSH_BYTES: u64 = 256 * 1024;

/// Wraps the *client* side of a proxied session so byte counts accrue as the copy runs rather
/// than at completion. Counting `copy_bidirectional`'s return value instead would lose every
/// byte of any session that ends by idle timeout or reset — i.e. most long-lived ones.
///
/// Counts are accumulated per connection and published to the shared `ListenerMetrics` only
/// every `COUNTER_FLUSH_BYTES` and on drop. A `fetch_add` per chunk would put a single shared
/// cache line in the path of every 8 KiB of proxied traffic, ping-ponging it across every core —
/// exactly the cross-core contention `SO_REUSEPORT` per worker exists to avoid.
///
/// Because it wraps the client, the direction naming is from the proxy's point of view: bytes
/// read here came *from* the client, bytes written here go *to* the client.
pub struct CountingStream<'a, S> {
	inner: S,
	listener_metrics: &'a ListenerMetrics,
	route_metrics: Option<&'a RouteMetrics>,
	pending_in: u64,
	pending_out: u64,
}

impl<'a, S> CountingStream<'a, S> {
	pub fn new(inner: S, listener_metrics: &'a ListenerMetrics, route_metrics: Option<&'a RouteMetrics>) -> Self {
		Self { inner, listener_metrics, route_metrics, pending_in: 0, pending_out: 0 }
	}

	fn publish_in(&self, bytes: u64) {
		self.listener_metrics.bytes_in.fetch_add(bytes, Ordering::Relaxed);
		if let Some(metrics) = self.route_metrics {
			metrics.bytes_in.fetch_add(bytes, Ordering::Relaxed);
		}
	}

	fn publish_out(&self, bytes: u64) {
		self.listener_metrics.bytes_out.fetch_add(bytes, Ordering::Relaxed);
		if let Some(metrics) = self.route_metrics {
			metrics.bytes_out.fetch_add(bytes, Ordering::Relaxed);
		}
	}

	fn record_in(&mut self, bytes: u64) {
		self.pending_in += bytes;
		if self.pending_in >= COUNTER_FLUSH_BYTES {
			self.publish_in(self.pending_in);
			self.pending_in = 0;
		}
	}

	fn record_out(&mut self, bytes: u64) {
		self.pending_out += bytes;
		if self.pending_out >= COUNTER_FLUSH_BYTES {
			self.publish_out(self.pending_out);
			self.pending_out = 0;
		}
	}
}

// Publishes whatever is left when the session ends — including when the connection task is
// aborted at shutdown, since that drops the future and with it this stream.
impl<S> Drop for CountingStream<'_, S> {
	fn drop(&mut self) {
		if self.pending_in > 0 {
			self.publish_in(self.pending_in);
		}
		if self.pending_out > 0 {
			self.publish_out(self.pending_out);
		}
	}
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<'_, S> {
	fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
		let this = self.get_mut();
		let before = buf.filled().len();
		let result = Pin::new(&mut this.inner).poll_read(cx, buf);
		if matches!(result, Poll::Ready(Ok(()))) {
			let read = buf.filled().len().saturating_sub(before);
			if read > 0 {
				this.record_in(read as u64);
			}
		}
		result
	}
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<'_, S> {
	fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
		let this = self.get_mut();
		let result = Pin::new(&mut this.inner).poll_write(cx, buf);
		if let Poll::Ready(Ok(written)) = &result {
			this.record_out(*written as u64);
		}
		result
	}

	fn poll_write_vectored(
		self: Pin<&mut Self>,
		cx: &mut Context<'_>,
		bufs: &[std::io::IoSlice<'_>],
	) -> Poll<std::io::Result<usize>> {
		let this = self.get_mut();
		let result = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
		if let Poll::Ready(Ok(written)) = &result {
			this.record_out(*written as u64);
		}
		result
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

	#[test]
	fn block_and_error_kinds_have_distinct_labels() {
		let mut labels: Vec<&str> = BlockKind::ALL.iter().map(|k| k.as_str()).collect();
		labels.sort_unstable();
		let count = labels.len();
		labels.dedup();
		assert_eq!(labels.len(), count, "BlockKind labels must be unique");

		let mut labels: Vec<&str> = ErrorKind::ALL.iter().map(|k| k.as_str()).collect();
		labels.sort_unstable();
		let count = labels.len();
		labels.dedup();
		assert_eq!(labels.len(), count, "ErrorKind labels must be unique");
	}

	#[test]
	fn per_reason_counts_sum_to_the_total() {
		let m = ListenerMetrics::default();
		m.inc_blocked(BlockKind::RateLimited);
		m.inc_blocked(BlockKind::RateLimited);
		m.inc_blocked(BlockKind::NoSni);
		m.inc_error(ErrorKind::UpstreamConnect);

		assert_eq!(total_of(&m.blocked_by_reason()), 3);
		assert_eq!(total_of(&m.errors_by_reason()), 1);

		// Every reason is exported, including the ones still at zero.
		assert_eq!(m.blocked_by_reason().len(), BlockKind::COUNT);
		assert_eq!(m.errors_by_reason().len(), ErrorKind::COUNT);
	}

	#[tokio::test]
	async fn counting_stream_publishes_both_directions_on_drop() {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};

		let metrics = ListenerMetrics::default();
		// duplex gives a paired in-memory stream; write into `peer` to be read through the counter.
		let (client, mut peer) = tokio::io::duplex(64);
		let mut counted = CountingStream::new(client, &metrics, None);

		peer.write_all(b"hello").await.unwrap();
		let mut buf = [0u8; 5];
		counted.read_exact(&mut buf).await.unwrap();
		counted.write_all(b"world!").await.unwrap();

		// Below the flush threshold, so the shared counters stay untouched until the session ends.
		assert_eq!(metrics.bytes_in.load(Ordering::Relaxed), 0);
		assert_eq!(metrics.bytes_out.load(Ordering::Relaxed), 0);

		drop(counted);
		assert_eq!(metrics.bytes_in.load(Ordering::Relaxed), 5);
		assert_eq!(metrics.bytes_out.load(Ordering::Relaxed), 6);
	}

	// A long-lived connection must not withhold its traffic from scrapes until it closes.
	#[tokio::test]
	async fn counting_stream_publishes_once_past_the_flush_threshold() {
		use tokio::io::AsyncWriteExt;

		let metrics = ListenerMetrics::default();
		let (client, mut peer) = tokio::io::duplex(COUNTER_FLUSH_BYTES as usize * 4);
		let mut counted = CountingStream::new(client, &metrics, None);

		let chunk = vec![0u8; 8 * 1024];
		let mut written = 0u64;
		while written < COUNTER_FLUSH_BYTES {
			counted.write_all(&chunk).await.unwrap();
			written += chunk.len() as u64;
		}

		assert_eq!(
			metrics.bytes_out.load(Ordering::Relaxed),
			written,
			"crossing the threshold must publish everything accumulated so far"
		);

		// Drain so the duplex peer doesn't hold the buffer, then confirm drop double-counts nothing.
		drop(counted);
		peer.shutdown().await.ok();
		assert_eq!(metrics.bytes_out.load(Ordering::Relaxed), written);
	}

	#[tokio::test]
	async fn counting_stream_publishes_to_listener_and_route() {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};

		let listener = ListenerMetrics::default();
		let route = RouteMetrics::default();
		let (client, mut peer) = tokio::io::duplex(64);
		let mut counted = CountingStream::new(client, &listener, Some(&route));

		peer.write_all(b"hello").await.unwrap();
		let mut buf = [0u8; 5];
		counted.read_exact(&mut buf).await.unwrap();
		counted.write_all(b"world!").await.unwrap();
		drop(counted);

		assert_eq!(listener.bytes_in.load(Ordering::Relaxed), 5);
		assert_eq!(listener.bytes_out.load(Ordering::Relaxed), 6);
		assert_eq!(route.bytes_in.load(Ordering::Relaxed), 5);
		assert_eq!(route.bytes_out.load(Ordering::Relaxed), 6);
	}

	#[test]
	fn route_errors_are_sparse_and_route_scoped() {
		let metrics = RouteMetrics::default();
		assert!(metrics.errors_by_reason().is_empty());

		metrics.inc_error(ErrorKind::UpstreamConnect);
		assert_eq!(metrics.errors_by_reason(), vec![("upstream_connect", 1)]);
	}

	#[test]
	fn route_active_gauge_does_not_underflow() {
		let metrics = Arc::new(RouteMetrics::default());
		let guard = RouteActiveGuard::new(metrics.clone());
		assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 1);
		assert_eq!(metrics.total_connections.load(Ordering::Relaxed), 1);
		drop(guard);
		assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
		metrics.dec_active();
		assert_eq!(metrics.active_connections.load(Ordering::Relaxed), 0);
	}
}
