/// Plaintext HTTP/1.1 listener for ACME HTTP-01 challenges and HTTP→HTTPS redirects.
///
/// Behaviour, per connection:
///   * Read the request headers.
///   * If the request target begins with `/.well-known/acme-challenge/`, look up
///     the route table by the `Host` header value (using the same wildcard rules
///     as SNI matching) and proxy the raw HTTP bytes to that route's first
///     upstream.  This lets the `letsencrypt-cert-generator-fabric` Harper
///     component answer the challenge on its existing HTTP port.
///   * Anything else returns `301 Moved Permanently` with
///     `Location: https://<host><request-target>`.
///
/// This is intended to replace the standalone nginx :80 on Fabric hosts so
/// symphony alone can bind to both ports.

use crate::http_proxy::{
	host_header, read_http_headers, request_target, strip_body_framing, with_connection_close,
};
use crate::listener::{make_reuseport_socket, set_rlimit_nofile};
use crate::proxy_conn::ConnContext;
use crate::upstream::{self, UpstreamStream};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{self, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::time::timeout;

const ACME_PATH_PREFIX: &[u8] = b"/.well-known/acme-challenge/";

/// Per-connection budget for reading the request headers off the wire.
/// Independent from the TLS handshake timeout so plain-HTTP attacks can't
/// trip the TLS protection counters.
const HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Bound the upstream connect attempt for the ACME proxy hop.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Same SO_REUSEPORT fanout as the TLS listener.
pub async fn spawn_http_listeners(
	addr: SocketAddr,
	workers: usize,
	max_connections: u32,
	ctx: Arc<ConnContext>,
	mut shutdown_rx: broadcast::Receiver<()>,
) -> crate::error::Result<()> {
	let workers = workers.max(1);

	if max_connections > 0 {
		set_rlimit_nofile(max_connections as u64 * 2 + 1024)?;
	}

	let mut handles = Vec::with_capacity(workers);

	for _ in 0..workers {
		let socket = make_reuseport_socket(addr)?;
		let listener = TcpListener::from_std(socket.into())?;
		let ctx2 = ctx.clone();
		let max_conn = max_connections;
		let srx = shutdown_rx.resubscribe();

		let handle = tokio::spawn(async move {
			accept_loop(listener, max_conn, ctx2, srx).await;
		});
		handles.push(handle);
	}

	let _ = shutdown_rx.recv().await;

	for h in handles {
		h.abort();
	}

	Ok(())
}

async fn accept_loop(
	listener: TcpListener,
	max_connections: u32,
	ctx: Arc<ConnContext>,
	mut shutdown_rx: broadcast::Receiver<()>,
) {
	loop {
		tokio::select! {
			_ = shutdown_rx.recv() => break,
			result = listener.accept() => {
				match result {
					Ok((stream, peer_addr)) => {
						if max_connections > 0 {
							let active = ctx.global_metrics.active_connections.load(std::sync::atomic::Ordering::Relaxed);
							if active >= max_connections as u64 {
								drop(stream);
								ctx.listener_metrics.inc_blocked();
								continue;
							}
						}
						let ctx2 = ctx.clone();
						tokio::spawn(async move {
							handle_http(stream, peer_addr, ctx2).await;
						});
					}
					Err(e) => {
						tracing::error!("accept error on {}: {e}", ctx.listener_addr);
						tokio::time::sleep(Duration::from_millis(10)).await;
					}
				}
			}
		}
	}
}

async fn handle_http(mut stream: TcpStream, peer_addr: SocketAddr, ctx: Arc<ConnContext>) {
	ctx.listener_metrics.inc_active();
	ctx.global_metrics.inc_active();

	let _guard = ActiveGuard {
		global: ctx.global_metrics.clone(),
		listener: ctx.listener_metrics.clone(),
	};

	// Read just the request line + headers. Capped by HEADER_READ_TIMEOUT so a
	// stalled client can't hold a worker hostage.
	let (headers, excess) = match timeout(HEADER_READ_TIMEOUT, read_http_headers(&mut stream)).await {
		Ok(Ok(pair)) => pair,
		Ok(Err(e)) => {
			tracing::debug!("http :80 header read error from {}: {e}", peer_addr.ip());
			ctx.listener_metrics.inc_error();
			return;
		}
		Err(_) => {
			tracing::debug!("http :80 header read timeout from {}", peer_addr.ip());
			ctx.listener_metrics.inc_error();
			return;
		}
	};

	if headers.is_empty() {
		// EOF before the header block completed.
		return;
	}

	let target = request_target(&headers);
	let host = host_header(&headers);

	if target.starts_with(ACME_PATH_PREFIX) {
		if let Some(host) = host {
			if proxy_acme(&mut stream, &headers, peer_addr, host, &ctx).await.is_err() {
				ctx.listener_metrics.inc_error();
			}
			return;
		}
		// Missing or unsafe Host header on an ACME request — fall through to a 400.
		let _ = write_simple_response(&mut stream, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
		return;
	}

	// Default: redirect to https://<host><target>.
	let Some(host) = host else {
		let _ = write_simple_response(&mut stream, b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
		return;
	};
	let target_str = std::str::from_utf8(target).unwrap_or("/");
	let target_str = if target_str.is_empty() { "/" } else { target_str };
	let location = format!("https://{host}{target_str}");
	let response = format!(
		"HTTP/1.1 301 Moved Permanently\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	);
	let _ = stream.write_all(response.as_bytes()).await;
	let _ = stream.shutdown().await;
}

async fn proxy_acme(
	client: &mut TcpStream,
	headers: &[u8],
	peer_addr: SocketAddr,
	host: &str,
	ctx: &ConnContext,
) -> std::io::Result<()> {
	let table = ctx.route_table.0.load();
	let Some(route) = table.resolve(Some(host)) else {
		// No matching route — answer 404 so the ACME client gets a definitive answer
		// rather than a hung connection.
		let _ = write_simple_response(client, b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
		return Ok(());
	};

	// Honour the route's global rate limit the same way the TLS path does, so
	// a flood of /.well-known/acme-challenge/ requests can't bypass the cap.
	if let Some(rl) = &route.rate_limiter {
		if !rl.try_acquire() {
			ctx.listener_metrics.inc_error();
			return Ok(());
		}
	}

	let upstream =
		upstream::connect(&route.destination, Some(peer_addr.ip()), UPSTREAM_CONNECT_TIMEOUT)
			.await
			.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

	// ACME HTTP-01 challenges are GET requests with no body.  Strip any
	// Content-Length / Transfer-Encoding headers so a client that lies about a
	// body (e.g. `Content-Length: 999999` with no payload) can't deadlock the
	// upstream waiting for bytes that will never arrive.  Then force
	// `Connection: close` so the upstream returns exactly one response and EOFs
	// — this gives us a clean read-to-EOF on the response side, and prevents
	// the connection from becoming a keep-alive tunnel that would let a client
	// pipeline non-ACME requests onto the same socket and bypass the HTTPS
	// redirect path.
	let forwarded = with_connection_close(&strip_body_framing(headers));

	let result = match upstream {
		UpstreamStream::Tcp(mut up) => proxy_one_shot(client, &mut up, &forwarded).await,
		UpstreamStream::Uds { mut stream, _guard } => {
			let r = proxy_one_shot(client, &mut stream, &forwarded).await;
			drop(_guard);
			r
		}
	};

	// Always close the client socket after one request/response, regardless of
	// the upstream outcome.  The HTTP-mode listener never reuses connections.
	let _ = client.shutdown().await;
	result
}

/// Send the (sanitized, body-less) request `headers` to `upstream`, then copy
/// the upstream's response back to `client`.  Strictly unidirectional after
/// the request bytes flush — any bytes the client already pipelined past the
/// header boundary are silently dropped, so no pipelined non-ACME payload can
/// reach the backend.
async fn proxy_one_shot<U>(
	client: &mut TcpStream,
	upstream: &mut U,
	headers: &[u8],
) -> std::io::Result<()>
where
	U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
	upstream.write_all(headers).await?;
	upstream.flush().await?;
	io::copy(upstream, client).await.map(|_| ())
}

async fn write_simple_response(stream: &mut TcpStream, response: &[u8]) -> std::io::Result<()> {
	stream.write_all(response).await?;
	stream.shutdown().await
}

struct ActiveGuard {
	global: Arc<crate::metrics::GlobalMetrics>,
	listener: Arc<crate::metrics::ListenerMetrics>,
}

impl Drop for ActiveGuard {
	fn drop(&mut self) {
		self.global.dec_active();
		self.listener.dec_active();
	}
}
