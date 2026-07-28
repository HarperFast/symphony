use crate::metrics::BlockKind;
use crate::proxy_conn::{ConnContext, handle};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::broadcast;

/// Spawn N accept loops for a single logical listener address,
/// using SO_REUSEPORT so the kernel distributes connections across them.
/// N = number of tokio worker threads (passed in as `workers`).
pub async fn spawn_listeners(
	addr: SocketAddr,
	workers: usize,
	max_connections: u32,
	ctx: Arc<ConnContext>,
	mut shutdown_rx: broadcast::Receiver<()>,
) -> crate::error::Result<()> {
	let workers = workers.max(1);

	// Raise RLIMIT_NOFILE if needed. Each connection needs 2 fds (client + upstream).
	// We attempt to set it to 2 * max_connections + 1024 headroom, capped at the hard limit.
	if max_connections > 0 {
		set_rlimit_nofile(max_connections as u64 * 2 + 1024)?;
	}

	let mut handles = Vec::with_capacity(workers);

	for _ in 0..workers {
		let socket = make_reuseport_socket(addr)?;
		let listener = TcpListener::from_std(socket)?;
		let ctx2 = ctx.clone();
		let max_conn = max_connections;
		let srx = shutdown_rx.resubscribe();

		let handle = tokio::spawn(async move {
			accept_loop(listener, max_conn, ctx2, srx).await;
		});
		handles.push(handle);
	}

	// Wait for shutdown signal
	let _ = shutdown_rx.recv().await;

	// Cancel all accept tasks
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
						let ctx2 = ctx.clone();
						tokio::spawn(async move {
							handle(stream, peer_addr, ctx2).await;
						});
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

pub(crate) fn make_reuseport_socket(addr: SocketAddr) -> crate::error::Result<std::net::TcpListener> {
	let domain = if addr.is_ipv6() { Domain::IPV6 } else { Domain::IPV4 };
	let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

	socket.set_reuse_address(true)?;
	socket.set_reuse_port(true)?; // SO_REUSEPORT — Linux 3.9+
	socket.set_nonblocking(true)?;
	socket.bind(&addr.into())?;
	socket.listen(65535)?;

	Ok(socket.into())
}

pub(crate) fn set_rlimit_nofile(desired: u64) -> crate::error::Result<()> {
	use libc::{getrlimit, rlimit, setrlimit, RLIMIT_NOFILE};

	let mut rlim = rlimit { rlim_cur: 0, rlim_max: 0 };
	let ret = unsafe { getrlimit(RLIMIT_NOFILE, &mut rlim) };
	if ret != 0 {
		return Ok(()); // Ignore if we can't query
	}

	let target = desired.min(rlim.rlim_max);
	if rlim.rlim_cur < target {
		let new_rlim = rlimit { rlim_cur: target, rlim_max: rlim.rlim_max };
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
