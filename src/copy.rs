//! Hand-rolled replacement for `tokio::io::copy_bidirectional_with_sizes` that does not hold a
//! per-direction buffer for the connection's whole life.
//!
//! `tokio::io::CopyBuffer` allocates its buffer once, before the first read, and keeps it for as
//! long as the copy future exists — i.e. for the whole proxied session, whether or not it is
//! actively transferring. For a mostly-idle connection (an MQTT subscriber parked between
//! publishes) that is dead weight: `readBufferSize` × 2 held in memory for a session that spends
//! nearly all its time doing nothing. `LazyCopyBuffer` below holds only a small fixed floor
//! (`PROBE_BUFFER_SIZE`) while idle or exchanging small discrete messages, escalating straight to
//! the full `max_buf_size` only once *two consecutive* reads land at capacity, and dropping
//! straight back to the floor once the direction actually parks with nothing left to write — not
//! on every single under-capacity read, which would shrink (and then immediately re-grow) a
//! connection that is still continuously active but simply has variably-sized traffic.
//! `readBufferSize` (and its per-direction overrides) becomes the *maximum* per-transfer buffer
//! size rather than a permanent allocation.
//!
//! None of this is unconditional. The saving scales with connection count and the cost does not,
//! so the escalate/shrink behavior is gated on the proxy's live active-connection count
//! (`LazyBufferGate`, configured by `lazyCopyBufferThreshold`). Below the threshold each direction
//! gets its full configured buffer once and never resizes — byte-for-byte the
//! `tokio::io::copy_bidirectional_with_sizes` behavior this module replaced — so a proxy carrying
//! a few bulk replication streams pays nothing for a memory problem it does not have. Above it,
//! everything below applies.
//!
//! Why two consecutive full reads, not one: escalating on a single full read means a message
//! that happens to exactly fill the current (small) buffer — coincidence, not evidence of a
//! burst — jumps straight to the configured maximum and then sits there for however long the
//! connection is next idle, which can be indefinite. Requiring a second consecutive full read
//! before jumping costs one extra small-buffer round trip on every genuine burst (negligible) and
//! bounds that single-message coincidence to the floor size instead of the configured maximum,
//! however large that maximum is configured.
//!
//! This is structured as a direct port of `tokio::io::util::copy::CopyBuffer` and
//! `copy_bidirectional`'s `transfer_one_direction`/`TransferState` (see the tokio source), with
//! the buffer-resize decision spliced into the point where a fully-drained buffer is reset for
//! the next read. Reusing that proven state machine — rather than `tokio::io::split` plus
//! independent per-direction `async fn`s — matters for two reasons: `split` wraps each side in an
//! `Arc<Mutex<_>>` (two heap allocations and a lock/unlock on every read/write/flush/shutdown,
//! *per connection*, which itself scales with connection count — exactly what this change exists
//! to avoid), and a hand-rolled `async fn` pump does not flush before parking on the next read the
//! way tokio's `poll_copy` does. That gap is real: `write_all` only guarantees the data reached
//! the writer's internal buffer, not the wire (`tokio-rustls` in particular defers sending
//! encrypted records until `poll_flush`). A TLS client that sends one request and then waits for
//! the reply would never see it — both sides would sit idle until `idle_timeout` cleaned up the
//! session — because the pump had already moved on to (blocking on) the next read before the
//! previous write was actually flushed.

use std::future::{poll_fn, Future};
use std::io;
use std::pin::Pin;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::metrics::GlobalMetrics;

/// Decides, at each resize point, whether escalating buffers are worth their cost *right now*.
///
/// The saving scales with connection count; the cost does not. Growing and releasing a buffer
/// costs two allocations plus the zeroing of `vec![0u8; n]` per burst, and a proxy carrying four
/// bulk replication streams pays that on every burst while saving a few hundred KiB it was never
/// short of. The same behavior across a hundred thousand parked MQTT subscribers is the whole
/// point of the module. So the behavior is gated on how busy the proxy actually is rather than
/// chosen once, fleet-wide, by whoever wrote the config.
///
/// `threshold` is the proxy-wide active connection count at or above which escalation engages.
/// `0` engages it always; a value above peak concurrency disables it, leaving each direction on a
/// full-size buffer allocated once — byte-for-byte the `tokio::io::copy_bidirectional_with_sizes`
/// behavior this module replaced, with no resize churn at all.
///
/// Deliberately re-read at every resize point rather than latched per connection. A connection
/// established while the proxy was quiet would otherwise hold a full-size buffer for its entire
/// life however busy the proxy later became — and long-lived connections accumulating while idle
/// is exactly the shape that motivates this. Re-reading means those connections start releasing
/// their buffers at their next park once the proxy crosses the threshold.
#[derive(Clone)]
pub struct LazyBufferGate {
	metrics: Arc<GlobalMetrics>,
	threshold: u64,
}

impl LazyBufferGate {
	pub fn new(metrics: Arc<GlobalMetrics>, threshold: u64) -> Self {
		Self { metrics, threshold }
	}

	/// `Relaxed` matches how the gauge is maintained and is all this needs: the result only picks
	/// a buffer size, so a read that is momentarily stale costs one connection one resize
	/// decision, never correctness.
	fn engaged(&self) -> bool {
		self.threshold == 0 || self.metrics.active_connections.load(Ordering::Relaxed) >= self.threshold
	}
}

#[cfg(test)]
impl LazyBufferGate {
	/// Engaged regardless of connection count — the escalate/release behavior under test.
	pub fn always() -> Self {
		Self::new(Arc::new(GlobalMetrics::default()), 0)
	}

	/// Never engaged — one full-size buffer per direction, held for the connection's life.
	pub fn never() -> Self {
		Self::new(Arc::new(GlobalMetrics::default()), u64::MAX)
	}

	/// A gate over a counter the test drives directly, for the threshold-crossing cases.
	pub fn with_metrics(metrics: Arc<GlobalMetrics>, threshold: u64) -> Self {
		Self::new(metrics, threshold)
	}
}

/// Resident buffer size while a direction is idle or only exchanging small, discrete messages
/// (PINGREQ, a short request). Deliberately tiny and fixed, not zero: a zero-length read buffer
/// makes `Ok(0)` ambiguous with EOF (see `proxy_conn::MIN_COPY_BUFFER_SIZE`), and a small constant
/// floor is a trivial, bounded cost — 1 KiB/connection total across both directions — next to a
/// configured max that can run up to 2 MiB/connection if held permanently the way
/// `tokio::io::CopyBuffer` holds it.
const PROBE_BUFFER_SIZE: usize = 512;

/// Copies bytes in both directions between `client` and `upstream`, mirroring
/// `tokio::io::copy_bidirectional_with_sizes`'s observable behavior:
/// - EOF on one reader shuts down the corresponding writer on the other stream ("half-close");
///   the other direction keeps running until it too reaches EOF or errors.
/// - An error on *either* direction — including a failed `shutdown()`, which tokio also
///   propagates — ends the whole copy immediately rather than waiting for the other direction.
///   This is what makes an RST on one leg end the session instead of hanging until idle_timeout.
///
/// `client_buf_size`/`upstream_buf_size` bound the buffer each direction may grow to; whether
/// either is held at that size permanently depends on `gate` (see `LazyBufferGate` and the module
/// docs).
pub async fn copy_bidirectional_lazy<C, U>(
	client: &mut C,
	upstream: &mut U,
	client_buf_size: usize,
	upstream_buf_size: usize,
	gate: LazyBufferGate,
) -> io::Result<()>
where
	C: AsyncRead + AsyncWrite + Unpin,
	U: AsyncRead + AsyncWrite + Unpin,
{
	let mut client_to_upstream = TransferState::Running(LazyCopyBuffer::new(client_buf_size, gate.clone()));
	let mut upstream_to_client = TransferState::Running(LazyCopyBuffer::new(upstream_buf_size, gate));
	poll_fn(|cx| {
		let a = transfer_one_direction(cx, &mut client_to_upstream, client, upstream)?;
		let b = transfer_one_direction(cx, &mut upstream_to_client, upstream, client)?;
		// It is not a problem if `ready!` returns early here: `transfer_one_direction` for the
		// side that already reached `Done` keeps returning `Poll::Ready(Ok(()))` on every future
		// call, so the other side's completion is picked up on a later poll.
		ready!(a);
		ready!(b);
		Poll::Ready(Ok(()))
	})
	.await
}

enum TransferState {
	Running(LazyCopyBuffer),
	ShuttingDown,
	Done,
}

fn transfer_one_direction<A, B>(
	cx: &mut Context<'_>,
	state: &mut TransferState,
	r: &mut A,
	w: &mut B,
) -> Poll<io::Result<()>>
where
	A: AsyncRead + AsyncWrite + Unpin + ?Sized,
	B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
	let mut r = Pin::new(r);
	let mut w = Pin::new(w);
	loop {
		match state {
			TransferState::Running(buf) => {
				ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
				*state = TransferState::ShuttingDown;
			}
			TransferState::ShuttingDown => {
				// Propagated, matching tokio: a shutdown failure (e.g. the peer already reset)
				// must end the copy the same as any other I/O error, not be silently ignored —
				// ignoring it would leave the *other* direction's `try`-equivalent waiting
				// forever for a completion that this side will never report.
				ready!(w.as_mut().poll_shutdown(cx))?;
				*state = TransferState::Done;
			}
			TransferState::Done => return Poll::Ready(Ok(())),
		}
	}
}

/// A single direction's copy buffer. Structurally a port of `tokio::io::util::copy::CopyBuffer`
/// with one addition: `buf` is resized (never merely indexed into a smaller slice) at the point
/// where a fully-drained buffer is reset for the next read, based on whether the read that just
/// filled it reached capacity.
struct LazyCopyBuffer {
	/// Floor size for this direction — `max_buf_size` itself if that is already ≤
	/// `PROBE_BUFFER_SIZE` (keeps tiny configured buffers, e.g. in tests, correct without special
	/// casing).
	small_size: usize,
	max_buf_size: usize,
	read_done: bool,
	need_flush: bool,
	pos: usize,
	cap: usize,
	buf: Vec<u8>,
	/// Consecutive read cycles that exactly saturated `buf`. Escalation requires two, not one —
	/// see the module docs for why a single full read isn't enough evidence of a sustained burst.
	full_streak: u32,
	/// Consulted at each resize point, not latched, so a connection follows the proxy's load
	/// rather than the conditions it happened to be established under. See `LazyBufferGate`.
	gate: LazyBufferGate,
}

impl LazyCopyBuffer {
	fn new(max_buf_size: usize, gate: LazyBufferGate) -> Self {
		let small_size = max_buf_size.min(PROBE_BUFFER_SIZE);
		// Start at the floor only if the gate is engaged. Disengaged, this allocates the full
		// buffer once and (with the shrink below equally gated) never resizes it again, which is
		// exactly what tokio's `CopyBuffer` did — so a proxy under the threshold pays none of
		// this module's churn, not a reduced amount of it.
		let initial_size = if gate.engaged() { small_size } else { max_buf_size };
		Self {
			small_size,
			max_buf_size,
			full_streak: 0,
			read_done: false,
			need_flush: false,
			pos: 0,
			cap: 0,
			buf: vec![0u8; initial_size],
			gate,
		}
	}

	fn poll_fill_buf<R>(&mut self, cx: &mut Context<'_>, reader: Pin<&mut R>) -> Poll<io::Result<()>>
	where
		R: AsyncRead + ?Sized,
	{
		let me = &mut *self;
		let mut buf = ReadBuf::new(&mut me.buf);
		buf.set_filled(me.cap);
		let res = reader.poll_read(cx, &mut buf);
		if let Poll::Ready(Ok(())) = res {
			let filled_len = buf.filled().len();
			// No new bytes were added by this call — `AsyncRead`'s contract for that is EOF.
			me.read_done = me.cap == filled_len;
			me.cap = filled_len;
		}
		res
	}

	fn poll_write_buf<R, W>(
		&mut self,
		cx: &mut Context<'_>,
		mut reader: Pin<&mut R>,
		mut writer: Pin<&mut W>,
	) -> Poll<io::Result<usize>>
	where
		R: AsyncRead + ?Sized,
		W: AsyncWrite + ?Sized,
	{
		let me = &mut *self;
		match writer.as_mut().poll_write(cx, &me.buf[me.pos..me.cap]) {
			Poll::Pending => {
				// Top up the buffer towards full if we can read a bit more data while the write
				// is blocked — improves the chances of a large write once it can proceed.
				if !me.read_done && me.cap < me.buf.len() {
					ready!(me.poll_fill_buf(cx, reader.as_mut()))?;
				}
				Poll::Pending
			}
			res => res,
		}
	}

	fn poll_copy<R, W>(&mut self, cx: &mut Context<'_>, mut reader: Pin<&mut R>, mut writer: Pin<&mut W>) -> Poll<io::Result<()>>
	where
		R: AsyncRead + ?Sized,
		W: AsyncWrite + ?Sized,
	{
		// Mirror tokio's own `CopyBuffer::poll_copy`: consume one unit of the task's
		// cooperative-scheduling budget on entry. Without this, a direction whose read and
		// write never return `Pending` (a fast loopback pair, or two directions that keep
		// topping each other off) can spin through this loop indefinitely inside one `poll`
		// call and monopolize its worker thread instead of yielding back to the scheduler.
		//
		// One deliberate divergence from tokio's own accounting: tokio's `poll_proceed` only
		// commits a budget unit when the poll goes on to make progress (`RestoreOnPending`
		// gives the unit back otherwise); this always commits on entry. A connection parked on
		// many no-progress wakeups therefore burns budget — and forces a coop yield — faster
		// here than tokio would. That's simpler (no progress-tracking to thread through this
		// port) and not unsafe: `consume_budget()` registers the waker before returning
		// `Pending` (`poll_proceed` → `register_waker`), so an early return here can't strand a
		// wakeup. It just yields somewhat more eagerly than tokio's own loop would.
		if std::pin::pin!(tokio::task::coop::consume_budget()).poll(cx).is_pending() {
			return Poll::Pending;
		}
		loop {
			if self.cap < self.buf.len() && !self.read_done {
				match self.poll_fill_buf(cx, reader.as_mut()) {
					Poll::Ready(Ok(())) => {}
					Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
					Poll::Pending => {
						// Ignore a pending read when there's still buffered data to write.
						if self.pos == self.cap {
							// Flush before parking so a writer that only sends on flush (e.g.
							// tokio-rustls, which defers ciphertext records) doesn't leave the
							// last write sitting unsent while this side waits for more input —
							// the other direction may be blocked waiting for exactly that reply.
							if self.need_flush {
								ready!(writer.as_mut().poll_flush(cx))?;
								self.need_flush = false;
							}
							// The buffer is fully drained and no more data is ready right now —
							// shrink to the floor before parking. Without this, a burst whose size
							// happens to land exactly on a buffer boundary ends by parking right
							// here still holding the escalated (max-sized) buffer: the shrink below
							// only runs after a *completed* under-capacity read, and if the
							// connection now goes idle — precisely the case this buffer exists to
							// keep cheap — that under-capacity read may never come. Shrinking here
							// costs the same one-round-trip re-escalation the design already pays
							// for growth, and a real sustained burst won't reach this branch (more
							// input is already buffered in the kernel, so the next read is Ready).
							//
							// Gated: below the threshold the buffer is left where it is, so a proxy
							// carrying a handful of bulk streams never pays a resize. Re-read here
							// rather than latched at construction, so a connection established while
							// the proxy was quiet does start releasing once it gets busy.
							if self.gate.engaged() && self.buf.len() > self.small_size {
								self.buf = vec![0u8; self.small_size];
							}
							self.full_streak = 0;
							return Poll::Pending;
						}
					}
				}
			}

			while self.pos < self.cap {
				let i = ready!(self.poll_write_buf(cx, reader.as_mut(), writer.as_mut()))?;
				if i == 0 {
					return Poll::Ready(Err(io::Error::new(io::ErrorKind::WriteZero, "write zero byte into writer")));
				}
				self.pos += i;
				self.need_flush = true;
			}

			// All data written — the buffer is empty again. Capture whether this cycle's read(s)
			// exactly saturated it *before* resetting, since that's the escalate/de-escalate
			// signal, then decide the next buffer size.
			let was_full = self.cap == self.buf.len();
			self.pos = 0;
			self.cap = 0;

			if self.read_done {
				ready!(writer.as_mut().poll_flush(cx))?;
				return Poll::Ready(Ok(()));
			}

			if was_full {
				self.full_streak += 1;
				if self.full_streak >= 2 && self.buf.len() < self.max_buf_size {
					// Two consecutive reads have now saturated the buffer — real evidence of a
					// sustained burst, not a single message that happened to match the current
					// size. Jump straight to the configured max: by this point more escalation
					// steps would only delay reaching full efficiency for no added safety.
					self.buf = vec![0u8; self.max_buf_size];
				}
			} else {
				// Came back under capacity — this cycle's burst evidence is gone, so require two
				// fresh full reads before escalating again. Deliberately does NOT shrink the
				// buffer here: a connection with continuously active but variably-sized traffic
				// (never actually idle) would otherwise reallocate on every undersized read only
				// to grow right back on the next burst — heap-thrashing a connection that never
				// stopped transferring. The buffer only shrinks once the direction actually parks
				// (see the `Poll::Pending` branch above), which is the one point that reliably
				// distinguishes "genuinely idle" from "momentarily between packets."
				self.full_streak = 0;
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::sync::atomic::{AtomicUsize, Ordering};
	use tokio::io::{AsyncReadExt, AsyncWriteExt};

	/// Distinguishable per byte, so a dropped or reordered chunk fails the assert.
	fn patterned(size: usize) -> Vec<u8> {
		(0..size).map(|i| (i % 251) as u8).collect()
	}

	#[tokio::test]
	async fn large_payload_integrity_through_a_small_buffer() {
		let (mut client, client_peer) = tokio::io::duplex(4096);
		let (mut upstream, mut upstream_peer) = tokio::io::duplex(4096);

		// 512× the 512-byte copy buffer configured below, so the loop must iterate many times.
		let payload = patterned(256 * 1024);

		let echo = tokio::spawn(async move {
			let mut buf = vec![0u8; 8192];
			loop {
				match upstream_peer.read(&mut buf).await {
					Ok(0) | Err(_) => break,
					Ok(n) => upstream_peer.write_all(&buf[..n]).await.unwrap(),
				}
			}
		});

		let (mut client_peer_read, mut client_peer_write) = tokio::io::split(client_peer);
		let to_send = payload.clone();
		let write_task = tokio::spawn(async move {
			client_peer_write.write_all(&to_send).await.unwrap();
			client_peer_write.shutdown().await.unwrap();
		});
		let read_task = tokio::spawn(async move {
			let mut buf = Vec::new();
			client_peer_read.read_to_end(&mut buf).await.unwrap();
			buf
		});

		let copy = copy_bidirectional_lazy(&mut client, &mut upstream, 512, 512, LazyBufferGate::always());
		let (copy_result, write_result, received) = tokio::join!(copy, write_task, read_task);
		copy_result.unwrap();
		write_result.unwrap();
		echo.await.unwrap();

		let received = received.unwrap();
		assert_eq!(received.len(), payload.len(), "no bytes dropped or duplicated");
		assert_eq!(received, payload, "payload round-trips byte-for-byte, in order");
	}

	struct ErroringReader {
		err_after: usize,
		read: usize,
	}

	impl AsyncRead for ErroringReader {
		fn poll_read(
			mut self: Pin<&mut Self>,
			_cx: &mut Context<'_>,
			buf: &mut ReadBuf<'_>,
		) -> Poll<io::Result<()>> {
			if self.read >= self.err_after {
				return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, "simulated RST")));
			}
			buf.put_slice(b"x");
			self.read += 1;
			Poll::Ready(Ok(()))
		}
	}

	/// Composes a reader half and a writer half into one `AsyncRead + AsyncWrite` type, for
	/// tests that need independent control over each side.
	struct RW<R, W> {
		r: R,
		w: W,
	}
	impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for RW<R, W> {
		fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
			let this = self.get_mut();
			Pin::new(&mut this.r).poll_read(cx, buf)
		}
	}
	impl<R: Unpin, W: AsyncWrite + Unpin> AsyncWrite for RW<R, W> {
		fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
			let this = self.get_mut();
			Pin::new(&mut this.w).poll_write(cx, buf)
		}
		fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			let this = self.get_mut();
			Pin::new(&mut this.w).poll_flush(cx)
		}
		fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			let this = self.get_mut();
			Pin::new(&mut this.w).poll_shutdown(cx)
		}
	}

	#[tokio::test]
	async fn rst_on_one_leg_ends_the_copy_immediately() {
		// The client leg errors after a few bytes; the upstream leg would otherwise read forever
		// (never returns Ready). The copy must still resolve promptly with the error, rather
		// than waiting on the upstream leg (that's what the idle timeout wrapping `forward()` is
		// for in a real hang — this test asserts the copy itself doesn't need it for an outright
		// I/O error).
		use tokio::io::duplex;

		let mut client = ErroringReader { err_after: 4, read: 0 };
		let (mut client_write_sink, _keep_alive) = duplex(64);
		let (mut upstream, _never_closes) = duplex(64);

		let mut client_rw = RW { r: &mut client, w: &mut client_write_sink };

		let result = tokio::time::timeout(
			std::time::Duration::from_secs(5),
			copy_bidirectional_lazy(&mut client_rw, &mut upstream, 512, 512, LazyBufferGate::always()),
		)
		.await
		.expect("copy must resolve promptly on RST, not hang for the upstream leg");

		assert!(result.is_err());
		assert_eq!(result.unwrap_err().kind(), io::ErrorKind::ConnectionReset);
	}

	#[tokio::test]
	async fn half_close_from_client_side_lets_upstream_direction_finish() {
		let (mut client, mut client_peer) = tokio::io::duplex(1024);
		let (mut upstream, mut upstream_peer) = tokio::io::duplex(1024);

		// Client sends nothing and closes immediately (write-half EOF); upstream still has data
		// queued for the client and must be allowed to deliver it before the copy completes.
		client_peer.shutdown().await.unwrap();
		let upstream_write = tokio::spawn(async move {
			upstream_peer.write_all(b"late data").await.unwrap();
			upstream_peer.shutdown().await.unwrap();
		});
		let read_task = tokio::spawn(async move {
			let mut buf = Vec::new();
			client_peer.read_to_end(&mut buf).await.unwrap();
			buf
		});

		copy_bidirectional_lazy(&mut client, &mut upstream, 512, 512, LazyBufferGate::always()).await.unwrap();
		upstream_write.await.unwrap();
		let received = read_task.await.unwrap();
		assert_eq!(received, b"late data");
	}

	#[tokio::test]
	async fn half_close_from_upstream_side_lets_client_direction_finish() {
		let (mut client, mut client_peer) = tokio::io::duplex(1024);
		let (mut upstream, mut upstream_peer) = tokio::io::duplex(1024);

		// Upstream sends nothing and closes immediately; the client still has data queued to send
		// upstream and must be allowed to deliver it (recorded by upstream_peer) before completion.
		upstream_peer.shutdown().await.unwrap();
		let client_write = tokio::spawn(async move {
			client_peer.write_all(b"queued request").await.unwrap();
			client_peer.shutdown().await.unwrap();
		});
		let read_task = tokio::spawn(async move {
			let mut buf = Vec::new();
			upstream_peer.read_to_end(&mut buf).await.unwrap();
			buf
		});

		copy_bidirectional_lazy(&mut client, &mut upstream, 512, 512, LazyBufferGate::always()).await.unwrap();
		client_write.await.unwrap();
		let received = read_task.await.unwrap();
		assert_eq!(received, b"queued request");
	}

	#[tokio::test]
	async fn single_byte_message_with_nothing_queued_behind_it_is_not_held_waiting_for_more() {
		// A lone byte (an MQTT PINGREQ, a short request) with no further data queued behind it
		// must be forwarded immediately, never held waiting for more that will never come.
		let (mut client, mut client_peer) = tokio::io::duplex(1024);
		let (mut upstream, mut upstream_peer) = tokio::io::duplex(1024);

		let echo = tokio::spawn(async move {
			let mut byte = [0u8; 1];
			upstream_peer.read_exact(&mut byte).await.unwrap();
			upstream_peer.write_all(&byte).await.unwrap();
			upstream_peer.shutdown().await.unwrap();
		});

		let driver = tokio::spawn(async move {
			client_peer.write_all(b"p").await.unwrap();
			let mut reply = [0u8; 1];
			client_peer.read_exact(&mut reply).await.unwrap();
			assert_eq!(&reply, b"p");
			client_peer.shutdown().await.unwrap();
		});

		tokio::time::timeout(
			std::time::Duration::from_secs(5),
			copy_bidirectional_lazy(&mut client, &mut upstream, 65536, 65536, LazyBufferGate::always()),
		)
		.await
		.expect("a single queued byte must be forwarded promptly, not held waiting for more")
		.unwrap();

		driver.await.unwrap();
		echo.await.unwrap();
	}

	/// A writer that only actually delivers bytes to `inner` on `poll_flush`, and counts flushes.
	/// Models a buffering transport like tokio-rustls, which documents that `poll_write` may not
	/// send all data and `poll_flush` must be called to guarantee it does.
	struct FlushGatedWriter<W> {
		inner: W,
		pending: Vec<u8>,
		flushes: std::sync::Arc<AtomicUsize>,
	}
	impl<W: AsyncRead + Unpin> AsyncRead for FlushGatedWriter<W> {
		fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
			let this = self.get_mut();
			Pin::new(&mut this.inner).poll_read(cx, buf)
		}
	}
	impl<W: AsyncWrite + Unpin> AsyncWrite for FlushGatedWriter<W> {
		fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
			let this = self.get_mut();
			this.pending.extend_from_slice(buf);
			Poll::Ready(Ok(buf.len()))
		}
		fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			let this = self.get_mut();
			if this.pending.is_empty() {
				return Pin::new(&mut this.inner).poll_flush(cx);
			}
			match Pin::new(&mut this.inner).poll_write(cx, &this.pending) {
				Poll::Ready(Ok(n)) => {
					this.pending.drain(..n);
					this.flushes.fetch_add(1, Ordering::SeqCst);
					if this.pending.is_empty() {
						Pin::new(&mut this.inner).poll_flush(cx)
					} else {
						Poll::Pending
					}
				}
				Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
				Poll::Pending => Poll::Pending,
			}
		}
		fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			let this = self.get_mut();
			Pin::new(&mut this.inner).poll_shutdown(cx)
		}
	}

	#[tokio::test]
	async fn write_is_flushed_before_parking_on_the_next_read() {
		// Regression test for the tokio-rustls-shaped deadlock: client sends one request,
		// upstream sends one short reply and then waits for the next request. If the
		// client-facing writer defers delivery until an explicit flush, and the pump doesn't
		// flush before blocking on the next client read, the reply sits undelivered forever.
		let (mut client, mut client_peer) = tokio::io::duplex(1024);
		let (upstream_side, mut upstream_peer) = tokio::io::duplex(1024);
		let flushes = std::sync::Arc::new(AtomicUsize::new(0));
		let mut upstream = FlushGatedWriter { inner: upstream_side, pending: Vec::new(), flushes: flushes.clone() };

		// Both peers are returned (not dropped) at the end of their task so the duplex stays
		// open — otherwise the task ending would drop its half, the copy would see a real EOF,
		// and the race below would be flaky depending on which finishes first.
		let echo = tokio::spawn(async move {
			let mut req = [0u8; 1];
			upstream_peer.read_exact(&mut req).await.unwrap();
			upstream_peer.write_all(b"reply").await.unwrap();
			// Upstream now waits indefinitely for the next request — nothing more is ever sent.
			upstream_peer
		});

		let driver = tokio::spawn(async move {
			client_peer.write_all(b"r").await.unwrap();
			let mut reply = [0u8; 5];
			client_peer.read_exact(&mut reply).await.unwrap();
			assert_eq!(&reply, b"reply");
			client_peer
		});

		// `upstream_peer` never sends anything more, so the copy itself runs forever; race it
		// against `driver` instead. The real assertion is that `driver` completes at all — its
		// `read_exact` only succeeds if the reply was actually flushed to the wire rather than
		// left buffered while the pump parked on the next (never-arriving) client read.
		let copy_fut = copy_bidirectional_lazy(&mut client, &mut upstream, 512, 512, LazyBufferGate::always());
		tokio::pin!(copy_fut);
		tokio::time::timeout(std::time::Duration::from_secs(5), async {
			tokio::select! {
				result = &mut copy_fut => panic!("copy must not complete while driver is still waiting: {result:?}"),
				driver_result = driver => driver_result.unwrap(),
			}
		})
		.await
		.expect("driver must complete — the reply must have been flushed to it");

		assert!(flushes.load(Ordering::SeqCst) > 0, "poll_flush must have been called to deliver the reply");
		echo.abort();
	}

	/// A writer whose `shutdown()` always fails, to prove shutdown errors are propagated rather
	/// than swallowed.
	struct FailingShutdownWriter<W> {
		inner: W,
	}
	impl<W: AsyncRead + Unpin> AsyncRead for FailingShutdownWriter<W> {
		fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
			let this = self.get_mut();
			Pin::new(&mut this.inner).poll_read(cx, buf)
		}
	}
	impl<W: AsyncWrite + Unpin> AsyncWrite for FailingShutdownWriter<W> {
		fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
			let this = self.get_mut();
			Pin::new(&mut this.inner).poll_write(cx, buf)
		}
		fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			let this = self.get_mut();
			Pin::new(&mut this.inner).poll_flush(cx)
		}
		fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			Poll::Ready(Err(io::Error::other("simulated shutdown failure")))
		}
	}

	#[tokio::test]
	async fn shutdown_failure_is_propagated_not_swallowed() {
		// The client leg reaches EOF, so its shutdown of the upstream writer runs — and that
		// shutdown fails. The whole copy must end with that error immediately; if the failure
		// were swallowed, this would instead hang waiting on the (otherwise-idle) upstream leg.
		let (mut client, client_peer) = tokio::io::duplex(64);
		drop(client_peer); // client reader hits EOF right away
		let (upstream_side, _never_closes) = tokio::io::duplex(64);
		let mut upstream = FailingShutdownWriter { inner: upstream_side };

		let result = tokio::time::timeout(
			std::time::Duration::from_secs(5),
			copy_bidirectional_lazy(&mut client, &mut upstream, 512, 512, LazyBufferGate::always()),
		)
		.await
		.expect("a failed shutdown must end the copy promptly, not hang waiting on the other direction");

		assert!(result.is_err());
		assert_eq!(result.unwrap_err().kind(), io::ErrorKind::Other);
	}

	#[tokio::test]
	async fn buffer_escalates_on_a_sustained_burst_and_shrinks_back_once_it_ends() {
		// max_buf_size well above PROBE_BUFFER_SIZE so both branches are actually reachable
		// (with max_buf_size <= 512 the "small" and "max" sizes are identical, and this test
		// would pass even with the escalate/de-escalate logic deleted entirely).
		const MAX: usize = 8192;
		let (mut client, mut client_peer) = tokio::io::duplex(MAX * 2);
		let (mut upstream, mut upstream_peer) = tokio::io::duplex(MAX * 2);

		let echo = tokio::spawn(async move {
			let mut buf = vec![0u8; MAX];
			loop {
				match upstream_peer.read(&mut buf).await {
					Ok(0) => break,
					Ok(n) => upstream_peer.write_all(&buf[..n]).await.unwrap(),
					Err(_) => break,
				}
			}
		});

		let driver = tokio::spawn(async move {
			// A burst several times larger than PROBE_BUFFER_SIZE, forcing escalation past two
			// consecutive full reads. This proves round-trip correctness *despite* the buffer
			// resizing mid-transfer, not that it actually resized — `buf_len_transitions_through_a_burst_and_back`
			// below inspects the buffer directly for that.
			let burst = vec![7u8; MAX * 4];
			client_peer.write_all(&burst).await.unwrap();
			let mut readback = vec![0u8; burst.len()];
			client_peer.read_exact(&mut readback).await.unwrap();
			assert_eq!(readback, burst, "burst round-trips byte-for-byte despite the escalating buffer");

			// Then a single small message — after a burst this size, an un-shrunk buffer would
			// still work, but the point of the fix is that it doesn't stay at the burst's size.
			client_peer.write_all(&[9u8]).await.unwrap();
			let mut one = [0u8; 1];
			client_peer.read_exact(&mut one).await.unwrap();
			assert_eq!(one[0], 9);

			client_peer.shutdown().await.unwrap();
		});

		tokio::time::timeout(
			std::time::Duration::from_secs(10),
			copy_bidirectional_lazy(&mut client, &mut upstream, MAX, MAX, LazyBufferGate::always()),
		)
		.await
		.expect("burst then small message must complete without stalling")
		.unwrap();
		driver.await.unwrap();
		echo.await.unwrap();
	}

	/// Drives `LazyCopyBuffer::poll_copy` directly (no sockets, no tokio scheduler) so the two
	/// state transitions the escalate/shrink design depends on can be asserted directly instead
	/// of inferred from end-to-end timing: `full_streak` reaching 2 grows `buf` to `max_buf_size`,
	/// and parking with nothing left to write (the burst has ended and the reader has nothing
	/// more ready) shrinks it back to `small_size`.
	#[test]
	fn buf_len_transitions_through_a_burst_and_back() {
		/// Fills every requested read fully (whatever the buffer's current capacity is) for the
		/// first `full_reads` calls, then a single byte (deliberately under capacity) to end the
		/// burst, then parks forever.
		struct BurstThenOneByte {
			full_reads: usize,
			calls: usize,
		}
		impl AsyncRead for BurstThenOneByte {
			fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
				self.calls += 1;
				if self.calls <= self.full_reads {
					let n = buf.remaining();
					buf.put_slice(&vec![7u8; n]);
					Poll::Ready(Ok(()))
				} else if self.calls == self.full_reads + 1 {
					buf.put_slice(&[9u8]);
					Poll::Ready(Ok(()))
				} else {
					Poll::Pending
				}
			}
		}

		/// Records the length of every write it receives and always accepts immediately.
		struct RecordingWriter(std::sync::Arc<std::sync::Mutex<Vec<usize>>>);
		impl AsyncWrite for RecordingWriter {
			fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
				self.0.lock().unwrap().push(buf.len());
				Poll::Ready(Ok(buf.len()))
			}
			fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
				Poll::Ready(Ok(()))
			}
			fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
				Poll::Ready(Ok(()))
			}
		}

		const MAX: usize = 8192;
		let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
		// Reads 1–2 (at the floor size) drive `full_streak` to 2 and trigger escalation; read 3
		// is the first one issued against the now-`MAX`-sized buffer, so it's the one that must
		// actually observe (and write out) the escalated size.
		let mut reader = BurstThenOneByte { full_reads: 3, calls: 0 };
		let mut writer = RecordingWriter(writes.clone());
		let mut lazy_buf = LazyCopyBuffer::new(MAX, LazyBufferGate::always());
		let small_size = lazy_buf.small_size;

		let waker = std::task::Waker::noop();
		let mut cx = Context::from_waker(waker);
		// A single call: `poll_copy`'s inner loop only ever returns on `Pending` or completion, so
		// it runs the two full reads, the escalation, the under-capacity read, and the shrink
		// entirely within this one call before parking on the reader's subsequent `Pending`.
		let result = lazy_buf.poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer));

		assert!(result.is_pending(), "reader parks after the burst ends, so this call must not resolve");
		assert_eq!(
			*writes.lock().unwrap(),
			vec![small_size, small_size, MAX, 1],
			"two floor-sized writes, then escalation to MAX on the third, then the under-capacity write that ends the burst"
		);
		assert_eq!(lazy_buf.buf.len(), small_size, "buffer must have shrunk back to the floor after the burst ended");
		assert_eq!(lazy_buf.full_streak, 0, "the under-capacity read must reset the streak");
	}

	/// Fills every read to the buffer's current capacity `full_reads` times, then returns one
	/// under-capacity byte to end the burst, then parks. Shared by the gate tests below.
	struct BurstThenPark {
		full_reads: usize,
		calls: usize,
	}
	impl AsyncRead for BurstThenPark {
		fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
			self.calls += 1;
			if self.calls <= self.full_reads {
				let n = buf.remaining();
				buf.put_slice(&vec![7u8; n]);
				Poll::Ready(Ok(()))
			} else if self.calls == self.full_reads + 1 {
				buf.put_slice(&[9u8]);
				Poll::Ready(Ok(()))
			} else {
				Poll::Pending
			}
		}
	}

	/// Accepts every write immediately and records its length.
	struct SizeRecordingWriter(std::sync::Arc<std::sync::Mutex<Vec<usize>>>);
	impl AsyncWrite for SizeRecordingWriter {
		fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
			self.0.lock().unwrap().push(buf.len());
			Poll::Ready(Ok(buf.len()))
		}
		fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			Poll::Ready(Ok(()))
		}
		fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
			Poll::Ready(Ok(()))
		}
	}

	/// Below the threshold the module must behave exactly like the `tokio::io::CopyBuffer` it
	/// replaced: one full-size allocation up front, no probing at the floor, and no shrink on
	/// park. This is the property that makes the gate worth having — a proxy carrying a few bulk
	/// streams pays *none* of the churn, not a reduced amount of it.
	#[test]
	fn a_disengaged_gate_allocates_full_size_once_and_never_resizes() {
		const MAX: usize = 8192;
		let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
		let mut reader = BurstThenPark { full_reads: 3, calls: 0 };
		let mut writer = SizeRecordingWriter(writes.clone());
		let mut lazy_buf = LazyCopyBuffer::new(MAX, LazyBufferGate::never());

		assert_eq!(lazy_buf.buf.len(), MAX, "a disengaged gate must allocate the full buffer up front, not the floor");

		let waker = std::task::Waker::noop();
		let mut cx = Context::from_waker(waker);
		let result = lazy_buf.poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer));

		assert!(result.is_pending(), "the reader parks after the burst");
		assert_eq!(
			*writes.lock().unwrap(),
			vec![MAX, MAX, MAX, 1],
			"every read should have been served at full size — no floor-sized probing"
		);
		assert_eq!(lazy_buf.buf.len(), MAX, "a disengaged gate must not shrink on park");
	}

	/// The gate is re-read at each resize point rather than latched at construction. A connection
	/// established while the proxy was quiet must start releasing its buffer once the proxy gets
	/// busy — otherwise long-lived connections that accumulate while idle, the exact shape this
	/// module exists for, would each keep a full-size buffer forever.
	#[test]
	fn crossing_the_threshold_makes_an_already_established_connection_release() {
		const MAX: usize = 8192;
		const THRESHOLD: u64 = 10;
		let metrics = Arc::new(GlobalMetrics::default());
		let gate = LazyBufferGate::with_metrics(metrics.clone(), THRESHOLD);

		// Established while quiet: full-size buffer, gate disengaged.
		let mut lazy_buf = LazyCopyBuffer::new(MAX, gate);
		assert_eq!(lazy_buf.buf.len(), MAX, "established below the threshold, so it starts full-size");
		let small_size = lazy_buf.small_size;

		// The proxy fills up. Exactly at the threshold, which must count as engaged.
		metrics.active_connections.store(THRESHOLD, Ordering::Relaxed);

		let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
		let mut reader = BurstThenPark { full_reads: 3, calls: 0 };
		let mut writer = SizeRecordingWriter(writes.clone());
		let waker = std::task::Waker::noop();
		let mut cx = Context::from_waker(waker);
		let result = lazy_buf.poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer));

		assert!(result.is_pending(), "the reader parks after the burst");
		assert_eq!(
			lazy_buf.buf.len(),
			small_size,
			"once active connections reach the threshold, the next park must release the full-size buffer"
		);
	}

	/// One below the threshold is still disengaged — the boundary is `>=`, and a test that only
	/// checked 0-vs-huge would not catch an off-by-one there.
	#[test]
	fn just_under_the_threshold_stays_disengaged() {
		const MAX: usize = 8192;
		const THRESHOLD: u64 = 10;
		let metrics = Arc::new(GlobalMetrics::default());
		metrics.active_connections.store(THRESHOLD - 1, Ordering::Relaxed);
		let lazy_buf = LazyCopyBuffer::new(MAX, LazyBufferGate::with_metrics(metrics.clone(), THRESHOLD));
		assert_eq!(lazy_buf.buf.len(), MAX, "one connection below the threshold must still be disengaged");

		metrics.active_connections.store(THRESHOLD, Ordering::Relaxed);
		let engaged_buf = LazyCopyBuffer::new(MAX, LazyBufferGate::with_metrics(metrics, THRESHOLD));
		assert_eq!(engaged_buf.buf.len(), engaged_buf.small_size, "at the threshold it must engage");
	}

	/// A single under-capacity read must NOT shrink the buffer while the connection is still
	/// actively transferring (more data already ready right after) — only parking does. Without
	/// this, a connection with continuously active but variably-sized traffic would reallocate on
	/// every undersized read only to grow right back on the next burst: heap-thrashing a
	/// connection that never actually went idle.
	#[test]
	fn a_single_undersized_read_mid_burst_does_not_shrink_the_buffer() {
		/// full reads, then one under-capacity read, then full reads again, then parks forever —
		/// modeling a connection that dips below capacity once but never actually goes idle.
		struct DipThenResumeBurst {
			calls: usize,
		}
		impl AsyncRead for DipThenResumeBurst {
			fn poll_read(mut self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
				self.calls += 1;
				match self.calls {
					1 | 2 | 3 | 5 => {
						let n = buf.remaining();
						buf.put_slice(&vec![7u8; n]);
						Poll::Ready(Ok(()))
					}
					4 => {
						buf.put_slice(&[9u8]);
						Poll::Ready(Ok(()))
					}
					_ => Poll::Pending,
				}
			}
		}

		struct RecordingWriter(std::sync::Arc<std::sync::Mutex<Vec<usize>>>);
		impl AsyncWrite for RecordingWriter {
			fn poll_write(self: Pin<&mut Self>, _cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
				self.0.lock().unwrap().push(buf.len());
				Poll::Ready(Ok(buf.len()))
			}
			fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
				Poll::Ready(Ok(()))
			}
			fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
				Poll::Ready(Ok(()))
			}
		}

		const MAX: usize = 8192;
		let writes = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
		let mut reader = DipThenResumeBurst { calls: 0 };
		let mut writer = RecordingWriter(writes.clone());
		let mut lazy_buf = LazyCopyBuffer::new(MAX, LazyBufferGate::always());
		let small_size = lazy_buf.small_size;

		let waker = std::task::Waker::noop();
		let mut cx = Context::from_waker(waker);
		let result = lazy_buf.poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer));

		assert!(result.is_pending(), "reader parks at the end, so this call must not resolve");
		assert_eq!(
			*writes.lock().unwrap(),
			vec![small_size, small_size, MAX, 1, MAX],
			"the write right after the under-capacity read must still be MAX-sized — the buffer must not have shrunk from the single dip"
		);
		// Only parking (the reader's final Pending) shrinks it — proven separately by the
		// previous test; here the point is that call 4 alone did not.
		assert_eq!(lazy_buf.buf.len(), small_size, "buffer shrinks once the reader actually parks");
	}
}
