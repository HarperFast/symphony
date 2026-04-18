use crate::balancer::{BalancerGuard, UdsBalancer};
use crate::router::Destination;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

/// An established connection to an upstream server.
pub enum UpstreamStream {
	Tcp(TcpStream),
	Uds {
		stream: UnixStream,
		/// Keep the guard alive for the duration of the connection.
		_guard: BalancerGuard,
	},
}

/// Connect to an upstream destination.
/// `peer_ip` is passed to UDS balancers for IP affinity.
pub async fn connect(destination: &Destination, peer_ip: Option<IpAddr>) -> crate::error::Result<UpstreamStream> {
	match destination {
		Destination::Tcp(addr) => {
			let stream = TcpStream::connect(addr).await?;
			stream.set_nodelay(true)?;
			Ok(UpstreamStream::Tcp(stream))
		}
		Destination::UdsSet(balancer) => connect_uds(balancer, peer_ip).await,
	}
}

async fn connect_uds(balancer: &Arc<UdsBalancer>, peer_ip: Option<IpAddr>) -> crate::error::Result<UpstreamStream> {
	let path = balancer
		.pick(peer_ip)
		.ok_or_else(|| crate::error::SymphonyError::Config("UDS balancer has no sockets configured".into()))?;

	let stream = UnixStream::connect(path.as_ref()).await?;

	// The guard increments the counter on construction and decrements on drop.
	let guard = BalancerGuard::new(balancer.clone(), path.to_string());

	Ok(UpstreamStream::Uds { stream, _guard: guard })
}

/// Write a PROXY protocol v1 header so the backend can recover the real client
/// IP and port.
///
/// Format: `PROXY TCP4 <src-ip> <dst-ip> <src-port> <dst-port>\r\n`
pub async fn write_proxy_v1_header<W: tokio::io::AsyncWrite + Unpin>(
	stream: &mut W,
	peer_addr: SocketAddr,
) -> std::io::Result<()> {
	let (proto, src_ip, dst_ip) = match peer_addr.ip() {
		IpAddr::V4(ip) => ("TCP4", ip.to_string(), "127.0.0.1".to_string()),
		IpAddr::V6(ip) => ("TCP6", ip.to_string(), "::1".to_string()),
	};
	// dst-port is 0 — a placeholder; the backend only reads src-ip and src-port.
	let header = format!("PROXY {proto} {src_ip} {dst_ip} {} 0\r\n", peer_addr.port());
	stream.write_all(header.as_bytes()).await
}

/// Read the first chunk of HTTP data from `client`, insert an
/// `X-Forwarded-For` header after the request line, write the modified
/// data to `upstream`, then return so the caller can proceed with
/// bidirectional copy for the remaining data.
///
/// If the initial read contains no `\r\n` (not a valid HTTP request),
/// the header is prepended before the data as a best-effort fallback.
pub async fn inject_x_forwarded_for<C, U>(
	client: &mut C,
	upstream: &mut U,
	peer_addr: SocketAddr,
) -> std::io::Result<()>
where
	C: tokio::io::AsyncRead + Unpin,
	U: tokio::io::AsyncWrite + Unpin,
{
	let mut buf = vec![0u8; 8192];
	let n = client.read(&mut buf).await?;
	if n == 0 {
		return Ok(());
	}
	let data = &buf[..n];

	let xff = format!("X-Forwarded-For: {}\r\n", peer_addr.ip());

	// Find the end of the HTTP request line (first \r\n)
	let insert_pos = data
		.windows(2)
		.position(|w| w == b"\r\n")
		.map(|p| p + 2) // insert after the \r\n
		.unwrap_or(0); // no \r\n found — prepend

	upstream.write_all(&data[..insert_pos]).await?;
	upstream.write_all(xff.as_bytes()).await?;
	upstream.write_all(&data[insert_pos..]).await?;

	Ok(())
}

// ── tokio::io::AsyncRead + AsyncWrite impls via delegation ────────────────────
// We need UpstreamStream to work with copy_bidirectional.
// The cleanest approach is to use tokio's split + Box<dyn ...> or an enum dispatch.
// We use a concrete enum with manual pin-projection via tokio::io::copy_bidirectional
// on the inner streams, invoked from proxy_conn.rs by matching on the variant.
//
// This avoids the overhead of dynamic dispatch on every read/write call.
// proxy_conn.rs handles the match and calls the appropriate copy_bidirectional.
