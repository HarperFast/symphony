use crate::balancer::{BalancerGuard, UdsBalancer};
use crate::router::Destination;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UnixStream};
use tokio::time::timeout;

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
/// `connect_timeout` caps the time spent waiting for the initial connection.
pub async fn connect(
	destination: &Destination,
	peer_ip: Option<IpAddr>,
	connect_timeout: Duration,
) -> crate::error::Result<UpstreamStream> {
	match destination {
		Destination::Tcp(addr) => {
			let stream = timeout(connect_timeout, TcpStream::connect(addr))
				.await
				.map_err(|_| {
					crate::error::SymphonyError::Io(std::io::Error::new(
						std::io::ErrorKind::TimedOut,
						"upstream connect timeout",
					))
				})??;
			stream.set_nodelay(true)?;
			Ok(UpstreamStream::Tcp(stream))
		}
		Destination::UdsSet(balancer) => connect_uds(balancer, peer_ip, connect_timeout).await,
	}
}

async fn connect_uds(
	balancer: &Arc<UdsBalancer>,
	peer_ip: Option<IpAddr>,
	connect_timeout: Duration,
) -> crate::error::Result<UpstreamStream> {
	let path = balancer
		.pick(peer_ip)
		.ok_or_else(|| crate::error::SymphonyError::Config("UDS balancer has no sockets configured".into()))?;

	let stream = timeout(connect_timeout, UnixStream::connect(path.as_ref()))
		.await
		.map_err(|_| {
			crate::error::SymphonyError::Io(std::io::Error::new(
				std::io::ErrorKind::TimedOut,
				"upstream connect timeout",
			))
		})??;

	// The guard increments the counter on construction and decrements on drop.
	let guard = BalancerGuard::new(balancer.clone(), path.to_string());

	Ok(UpstreamStream::Uds { stream, _guard: guard })
}

/// Write a PROXY protocol v1 header to a Unix domain socket upstream so the
/// backend can recover the real client IP and port despite the UDS transport.
///
/// Format: `PROXY TCP4 <src-ip> <dst-ip> <src-port> <dst-port>\r\n`
pub async fn write_proxy_v1_header(stream: &mut UnixStream, peer_addr: SocketAddr) -> std::io::Result<()> {
	let (proto, src_ip, dst_ip) = match peer_addr.ip() {
		IpAddr::V4(ip) => ("TCP4", ip.to_string(), "127.0.0.1".to_string()),
		// Unwrap IPv4-mapped IPv6 (::ffff:1.2.3.4) to plain TCP4 so backends that
		// parse the PROXY header (HAProxy, nginx) receive a well-formed IPv4 address.
		IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
			Some(v4) => ("TCP4", v4.to_string(), "127.0.0.1".to_string()),
			None => ("TCP6", ip.to_string(), "::1".to_string()),
		},
	};
	// dst-port is 0 — a placeholder; the backend only reads src-ip and src-port.
	let header = format!("PROXY {proto} {src_ip} {dst_ip} {} 0\r\n", peer_addr.port());
	stream.write_all(header.as_bytes()).await
}

// ── tokio::io::AsyncRead + AsyncWrite impls via delegation ────────────────────
// We need UpstreamStream to work with copy_bidirectional.
// The cleanest approach is to use tokio's split + Box<dyn ...> or an enum dispatch.
// We use a concrete enum with manual pin-projection via tokio::io::copy_bidirectional
// on the inner streams, invoked from proxy_conn.rs by matching on the variant.
//
// This avoids the overhead of dynamic dispatch on every read/write call.
// proxy_conn.rs handles the match and calls the appropriate copy_bidirectional.
