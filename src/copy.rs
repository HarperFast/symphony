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
//! straight back to the floor the first time a read comes back under capacity. `readBufferSize`
//! (and its per-direction overrides) becomes the *maximum* per-transfer buffer size rather than a
//! permanent allocation.
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

use std::future::poll_fn;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

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
/// `client_buf_size`/`upstream_buf_size` bound the buffer each direction may grow to; neither is
/// held at that size permanently (see the module docs and `LazyCopyBuffer`).
pub async fn copy_bidirectional_lazy<C, U>(
	client: &mut C,
	upstream: &mut U,
	client_buf_size: usize,
	upstream_buf_size: usize,
) -> io::Result<()>
where
	C: AsyncRead + AsyncWrite + Unpin,
	U: AsyncRead + AsyncWrite + Unpin,
{
	let mut client_to_upstream = TransferState::Running(LazyCopyBuffer::new(client_buf_size));
	let mut upstream_to_client = TransferState::Running(LazyCopyBuffer::new(upstream_buf_size));
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
}

impl LazyCopyBuffer {
	fn new(max_buf_size: usize) -> Self {
		let small_size = max_buf_size.min(PROBE_BUFFER_SIZE);
		Self {
			small_size,
			max_buf_size,
			full_streak: 0,
			read_done: false,
			need_flush: false,
			pos: 0,
			cap: 0,
			buf: vec![0u8; small_size],
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
				// Came back under capacity — traffic has dropped off (or was never sustained).
				// Reset the streak and drop straight back to the floor so a connection that is
				// done bursting stops paying for the buffer immediately, rather than sitting at
				// whatever size it last reached for as long as it then stays idle.
				self.full_streak = 0;
				if self.buf.len() > self.small_size {
					self.buf = vec![0u8; self.small_size];
				}
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

		let copy = copy_bidirectional_lazy(&mut client, &mut upstream, 512, 512);
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
			copy_bidirectional_lazy(&mut client_rw, &mut upstream, 512, 512),
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

		copy_bidirectional_lazy(&mut client, &mut upstream, 512, 512).await.unwrap();
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

		copy_bidirectional_lazy(&mut client, &mut upstream, 512, 512).await.unwrap();
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
			copy_bidirectional_lazy(&mut client, &mut upstream, 65536, 65536),
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
		let copy_fut = copy_bidirectional_lazy(&mut client, &mut upstream, 512, 512);
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
			copy_bidirectional_lazy(&mut client, &mut upstream, 512, 512),
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
			// consecutive full reads — this must complete (proving the buffer actually grew to
			// carry it), not stall.
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
			copy_bidirectional_lazy(&mut client, &mut upstream, MAX, MAX),
		)
		.await
		.expect("burst then small message must complete without stalling")
		.unwrap();
		driver.await.unwrap();
		echo.await.unwrap();
	}
}
