use crate::balancer::{BalancerGuard, UdsBalancer};
use crate::router::Destination;
use std::net::IpAddr;
use std::sync::Arc;
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

// ── tokio::io::AsyncRead + AsyncWrite impls via delegation ────────────────────
// We need UpstreamStream to work with copy_bidirectional.
// The cleanest approach is to use tokio's split + Box<dyn ...> or an enum dispatch.
// We use a concrete enum with manual pin-projection via tokio::io::copy_bidirectional
// on the inner streams, invoked from proxy_conn.rs by matching on the variant.
//
// This avoids the overhead of dynamic dispatch on every read/write call.
// proxy_conn.rs handles the match and calls the appropriate copy_bidirectional.
