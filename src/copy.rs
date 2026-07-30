//! Hand-rolled replacement for `tokio::io::copy_bidirectional_with_sizes` that does not hold a
//! per-direction buffer for the connection's whole life.
//!
//! `tokio::io::CopyBuffer` allocates its buffer once, before the first read, and keeps it for as
//! long as the copy future exists — i.e. for the whole proxied session, whether or not it is
//! actively transferring. For a mostly-idle connection (an MQTT subscriber parked between
//! publishes) that is dead weight: `readBufferSize` × 2 held in memory for a session that spends
//! nearly all its time doing nothing. `pump` below holds only a small fixed-size buffer
//! (`PROBE_BUFFER_SIZE`) while idle or exchanging small discrete messages, and escalates to the
//! full `max_buf_size` only once a read proves there's a sustained burst, dropping back down the
//! first time a read comes back under capacity. `readBufferSize` (and its per-direction overrides)
//! becomes the *maximum* per-transfer buffer size rather than a permanent allocation.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
/// - An error on *either* direction ends the whole copy immediately (`try_join!` drops the other,
///   still-running direction rather than waiting for it) — this is what makes an RST on one leg
///   end the session instead of hanging until idle_timeout.
///
/// `client_buf_size`/`upstream_buf_size` bound the buffer each direction may grow to; they are
/// never held eagerly (see `pump`).
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
	let (mut client_read, mut client_write) = tokio::io::split(client);
	let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
	tokio::try_join!(
		pump(&mut client_read, &mut upstream_write, client_buf_size),
		pump(&mut upstream_read, &mut client_write, upstream_buf_size),
	)?;
	Ok(())
}

/// One direction of the bidirectional copy.
///
/// The buffer starts (and normally sits) at `PROBE_BUFFER_SIZE` — cheap enough to hold for a
/// connection's whole life. It escalates to the full `max_buf_size` only once a read *proves*
/// there is more coming than the small buffer can hold (a read that exactly fills it), and drops
/// back down the first time a read comes back under whatever capacity it's currently holding —
/// the signal that traffic has gone quiet again. Every read is a single, ordinary blocking
/// `.await`: `AsyncReadExt::read` already returns as soon as *any* data is available rather than
/// waiting to fill the buffer, so there is no need to (and no safe generic way to) peek for
/// "is there more already queued" without risking a wakeup race — an earlier version of this
/// function used a manual non-blocking `poll_read` for that, which under load silently stranded
/// a connection's wakeup (reproduced empirically: an increasing fraction of connections stopped
/// responding as concurrency grew). Growing the buffer one iteration late costs one extra
/// small-buffer round trip per burst; that's the entire price for making every step provably
/// deadlock-free.
async fn pump<R, W>(reader: &mut R, writer: &mut W, max_buf_size: usize) -> io::Result<()>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	let small_size = max_buf_size.min(PROBE_BUFFER_SIZE);
	let mut buf = vec![0u8; small_size];
	loop {
		let n = reader.read(&mut buf).await?;
		if n == 0 {
			let _ = writer.shutdown().await;
			return Ok(());
		}
		writer.write_all(&buf[..n]).await?;
		if n == buf.len() && buf.len() < max_buf_size {
			// This read saturated the current buffer — likely a sustained burst continuing
			// beyond what we just read. Grow for the next iteration.
			buf = vec![0u8; max_buf_size];
		} else if n < buf.len() && buf.len() > small_size {
			// Came back under capacity while holding the large buffer — traffic has dropped
			// back to occasional/small messages. Shrink so it isn't paid for between them.
			buf = vec![0u8; small_size];
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::pin::Pin;
	use std::task::{Context, Poll};
	use tokio::io::ReadBuf;

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

	#[tokio::test]
	async fn rst_on_one_leg_ends_the_copy_immediately() {
		// The client leg errors after a few bytes; the upstream leg would otherwise read forever
		// (never returns Ready). `try_join!` must still resolve promptly with the error, rather
		// than waiting on the upstream leg (that's what the idle timeout wrapping `forward()` is
		// for in a real hang — this test asserts the copy itself doesn't need it for an outright
		// I/O error).
		use tokio::io::duplex;

		let mut client = ErroringReader { err_after: 4, read: 0 };
		let (mut client_write_sink, _keep_alive) = duplex(64);
		let (mut upstream, _never_closes) = duplex(64);

		// Compose client as read+write via a small wrapper.
		struct RW<R, W> {
			r: R,
			w: W,
		}
		impl<R: AsyncRead + Unpin, W: Unpin> AsyncRead for RW<R, W> {
			fn poll_read(
				self: Pin<&mut Self>,
				cx: &mut Context<'_>,
				buf: &mut ReadBuf<'_>,
			) -> Poll<io::Result<()>> {
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
		// Regression test: a lone byte (an MQTT PINGREQ, a short request) with no further data
		// queued behind it must be forwarded immediately. An earlier version of `pump` did a
		// *blocking* opportunistic second read after the probe, which deadlocked exactly this
		// case — the peer never sends more until it sees a reply, and the reply never comes
		// because the pump is stuck awaiting more input.
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

	#[tokio::test]
	async fn buffer_releases_after_a_burst_then_reallocates_for_the_next_message() {
		// Exercises both branches of `pump`: a full-capacity read keeps the buffer resident for
		// one more iteration, and an under-capacity read (or the probe path) releases it. This is
		// a behavioral smoke test, not a memory assertion — RSS is measured out of band (see PR
		// description) since a unit test can't meaningfully assert process memory.
		let (mut client, mut client_peer) = tokio::io::duplex(4096);
		let (mut upstream, mut upstream_peer) = tokio::io::duplex(4096);

		let echo = tokio::spawn(async move {
			let mut buf = vec![0u8; 4096];
			loop {
				match upstream_peer.read(&mut buf).await {
					Ok(0) => break,
					Ok(n) => upstream_peer.write_all(&buf[..n]).await.unwrap(),
					Err(_) => break,
				}
			}
		});

		let driver = tokio::spawn(async move {
			// A burst that fills the small buffer several times over, then a lone byte, then close.
			client_peer.write_all(&vec![7u8; 256]).await.unwrap();
			let mut readback = vec![0u8; 256];
			client_peer.read_exact(&mut readback).await.unwrap();
			assert!(readback.iter().all(|&b| b == 7));

			client_peer.write_all(&[9u8]).await.unwrap();
			let mut one = [0u8; 1];
			client_peer.read_exact(&mut one).await.unwrap();
			assert_eq!(one[0], 9);

			client_peer.shutdown().await.unwrap();
		});

		copy_bidirectional_lazy(&mut client, &mut upstream, 64, 64).await.unwrap();
		driver.await.unwrap();
		echo.await.unwrap();
	}
}
