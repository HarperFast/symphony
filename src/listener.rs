use crate::liveness::{arm_accepted, arm_keepalive, KeepaliveConfig};
use crate::metrics::BlockKind;
use crate::proxy_conn::{handle, ConnContext};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

/// Bind N sockets for one listener address with SO_REUSEPORT, so the kernel distributes
/// connections across N accept loops (N = tokio worker threads). Must run inside the proxy
/// runtime: `TcpListener::from_std` registers with its reactor.
pub fn bind_workers(
	addr: SocketAddr,
	workers: usize,
	keepalive: Option<&KeepaliveConfig>,
) -> crate::error::Result<Vec<TcpListener>> {
	(0..workers.max(1))
		.map(|_| {
			Ok(TcpListener::from_std(make_reuseport_socket(
				addr, keepalive,
			)?)?)
		})
		.collect()
}

pub async fn spawn_listeners(
	listeners: Vec<TcpListener>,
	max_connections: u32,
	ctx: Arc<ConnContext>,
	mut shutdown_rx: broadcast::Receiver<()>,
) {
	let handles: Vec<_> = listeners
		.into_iter()
		.map(|listener| {
			tokio::spawn(accept_loop(
				listener,
				max_connections,
				ctx.clone(),
				shutdown_rx.resubscribe(),
			))
		})
		.collect();

	// Wait for shutdown signal
	let _ = shutdown_rx.recv().await;

	// Cancel all accept tasks
	for h in handles {
		h.abort();
	}
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
						// Fast connection limit check using global atomic
						if max_connections > 0 {
							let active = ctx.global_metrics.active_connections.load(std::sync::atomic::Ordering::Relaxed);
							if active >= max_connections as u64 {
								// Drop the stream — OS will send RST
								drop(stream);
								ctx.listener_metrics.inc_blocked(BlockKind::MaxConnections);
								continue;
							}
						}
						if let Some(cfg) = &ctx.keepalive {
							arm_accepted(&stream, cfg);
						}
						tokio::spawn(handle(stream, peer_addr, ctx.clone()));
					}
					Err(e) => {
						tracing::error!("accept error on {}: {e}", ctx.listener_addr);
						// Brief pause to avoid a tight error loop
						tokio::time::sleep(Duration::from_millis(10)).await;
					}
				}
			}
		}
	}
}

pub(crate) fn make_reuseport_socket(
	addr: SocketAddr,
	keepalive: Option<&KeepaliveConfig>,
) -> crate::error::Result<std::net::TcpListener> {
	let domain = if addr.is_ipv6() {
		Domain::IPV6
	} else {
		Domain::IPV4
	};
	let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

	socket.set_reuse_address(true)?;
	socket.set_reuse_port(true)?; // SO_REUSEPORT — Linux 3.9+
	socket.set_nonblocking(true)?;
	// Before listen(), so no accepted socket can predate the schedule it inherits.
	if let Some(cfg) = keepalive {
		arm_keepalive(&socket, cfg, &addr);
	}
	socket.bind(&addr.into())?;
	socket.listen(65535)?;

	Ok(socket.into())
}

pub(crate) fn set_rlimit_nofile(desired: u64) -> crate::error::Result<()> {
	use libc::{getrlimit, rlimit, setrlimit, RLIMIT_NOFILE};

	let mut rlim = rlimit {
		rlim_cur: 0,
		rlim_max: 0,
	};
	let ret = unsafe { getrlimit(RLIMIT_NOFILE, &mut rlim) };
	if ret != 0 {
		return Ok(()); // Ignore if we can't query
	}

	let target = desired.min(rlim.rlim_max);
	if rlim.rlim_cur < target {
		let new_rlim = rlimit {
			rlim_cur: target,
			rlim_max: rlim.rlim_max,
		};
		let ret = unsafe { setrlimit(RLIMIT_NOFILE, &new_rlim) };
		if ret != 0 {
			tracing::warn!(
				"Could not raise RLIMIT_NOFILE to {target}. Current limit: {}. \
				 On musl targets the hard limit may be lower than expected.",
				rlim.rlim_cur
			);
		}
	}
	Ok(())
}
