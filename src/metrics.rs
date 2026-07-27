use crate::protection::BlockReason;
use std::pin::Pin;
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
	/// The proxied session hit the idle timeout.
	IdleTimeout => "idle_timeout",
	/// I/O error while proxying an established session.
	Stream => "stream",
	/// HTTP-mode listener could not read the request head.
	HttpHeader => "http_header",
});

/// Per-listener counters. Every field is `Relaxed` — these are monotonic counters and gauges
/// read out of band by `metrics()`, never used to make a decision that needs ordering.
pub struct ListenerMetrics {
	pub active_connections: AtomicU64,
	pub total_accepted: AtomicU64,
	pub total_blocked: AtomicU64,
	pub total_errors: AtomicU64,
	/// Bytes read from clients on this listener (client → upstream). Counted at the point the
	/// proxy sees them, so a terminated-TLS route counts plaintext and a passthrough route
	/// counts wire bytes; neither includes the handshake, which precedes the counter.
	pub bytes_in: AtomicU64,
	/// Bytes written to clients on this listener (upstream → client). Same framing caveat as
	/// `bytes_in`.
	pub bytes_out: AtomicU64,
	blocked_by_kind: [AtomicU64; BlockKind::COUNT],
	errors_by_kind: [AtomicU64; ErrorKind::COUNT],
}

impl Default for ListenerMetrics {
	fn default() -> Self {
		Self {
			active_connections: AtomicU64::new(0),
			total_accepted: AtomicU64::new(0),
			total_blocked: AtomicU64::new(0),
			total_errors: AtomicU64::new(0),
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
		self.total_blocked.fetch_add(1, Ordering::Relaxed);
		self.blocked_by_kind[kind as usize].fetch_add(1, Ordering::Relaxed);
	}

	pub fn inc_error(&self, kind: ErrorKind) {
		self.total_errors.fetch_add(1, Ordering::Relaxed);
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

#[derive(Default)]
pub struct GlobalMetrics {
	pub active_connections: AtomicU64,
	pub total_blocked: AtomicU64,
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

	pub fn inc_blocked(&self) {
		self.total_blocked.fetch_add(1, Ordering::Relaxed);
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

/// Wraps the *client* side of a proxied session so byte counts accrue as the copy runs rather
/// than at completion. Counting `copy_bidirectional`'s return value instead would lose every
/// byte of any session that ends by idle timeout or reset — i.e. most long-lived ones.
///
/// Because it wraps the client, the direction naming is from the proxy's point of view: bytes
/// read here came *from* the client, bytes written here go *to* the client.
pub struct CountingStream<'a, S> {
	inner: S,
	metrics: &'a ListenerMetrics,
}

impl<'a, S> CountingStream<'a, S> {
	pub fn new(inner: S, metrics: &'a ListenerMetrics) -> Self {
		Self { inner, metrics }
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
				this.metrics.bytes_in.fetch_add(read as u64, Ordering::Relaxed);
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
			this.metrics.bytes_out.fetch_add(*written as u64, Ordering::Relaxed);
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
			this.metrics.bytes_out.fetch_add(*written as u64, Ordering::Relaxed);
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

		let blocked: u64 = m.blocked_by_reason().iter().map(|(_, v)| v).sum();
		assert_eq!(blocked, m.total_blocked.load(Ordering::Relaxed));
		assert_eq!(blocked, 3);

		let errors: u64 = m.errors_by_reason().iter().map(|(_, v)| v).sum();
		assert_eq!(errors, m.total_errors.load(Ordering::Relaxed));
		assert_eq!(errors, 1);

		// Every reason is exported, including the ones still at zero.
		assert_eq!(m.blocked_by_reason().len(), BlockKind::COUNT);
		assert_eq!(m.errors_by_reason().len(), ErrorKind::COUNT);
	}

	#[tokio::test]
	async fn counting_stream_records_both_directions() {
		use tokio::io::{AsyncReadExt, AsyncWriteExt};

		let metrics = ListenerMetrics::default();
		// duplex gives a paired in-memory stream; write into `peer` to be read through the counter.
		let (client, mut peer) = tokio::io::duplex(64);
		let mut counted = CountingStream::new(client, &metrics);

		peer.write_all(b"hello").await.unwrap();
		let mut buf = [0u8; 5];
		counted.read_exact(&mut buf).await.unwrap();
		counted.write_all(b"world!").await.unwrap();

		assert_eq!(metrics.bytes_in.load(Ordering::Relaxed), 5);
		assert_eq!(metrics.bytes_out.load(Ordering::Relaxed), 6);
	}
}
