use crate::metrics::{GlobalMetrics, ListenerMetrics};
use crate::protection::ProtectionState;
use crate::router::{Destination, LiveRouteTable, SourceAddressMode};
use crate::sni;
use crate::suspended::SuspendedRegistry;
use crate::upstream::{self, UpstreamStream};
use napi::threadsafe_function::ThreadsafeFunction;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use std::marker::Unpin;
use tokio::io::copy_bidirectional;
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;

/// JS event types emitted from connection tasks back to Node.
#[derive(Debug)]
pub enum JsEvent {
	Blocked {
		ip: String,
		reason: String,
		listener: String,
		/// JA3 fingerprint (32-char hex) if parsed; empty string otherwise.
		ja3: String,
		/// JA4 fingerprint if parsed; empty string otherwise.
		ja4: String,
	},
	Suspended {
		id: String,
		sni: String,
		peer_ip: String,
		peer_port: u16,
		listener: String,
	},
	Error {
		message: String,
		listener: String,
	},
}

pub struct ConnContext {
	pub route_table: Arc<LiveRouteTable>,
	pub protection: Option<Arc<ProtectionState>>,
	pub suspended_registry: Arc<SuspendedRegistry>,
	pub global_metrics: Arc<GlobalMetrics>,
	pub listener_metrics: Arc<ListenerMetrics>,
	pub listener_addr: String,
	/// Idle timeout for the bidirectional copy phase. Zero means no timeout.
	pub idle_timeout: Duration,
	/// Timeout for establishing upstream connections (TCP connect / UDS connect).
	pub upstream_connect_timeout: Duration,
	pub read_buffer_size: usize,
	pub js_emit: Arc<ThreadsafeFunction<JsEvent>>,
}

pub async fn handle(stream: TcpStream, peer_addr: SocketAddr, ctx: Arc<ConnContext>) {
	let peer_ip = peer_addr.ip();

	// ── 1. Peek: extract SNI + JA3 ───────────────────────────────────────────
	let peek_info = sni::peek(&stream).await;

	// ── 2. Protection checks ─────────────────────────────────────────────────
	// `protection_counted` is true when check() incremented the active counter,
	// meaning the ActiveGuard must call release() on drop.
	let protection_counted = if let Some(protection) = &ctx.protection {
		match protection.check(peer_ip, &peek_info) {
			crate::protection::Decision::Block(reason) => {
				ctx.listener_metrics.inc_blocked();
				ctx.global_metrics.inc_blocked();
				emit(&ctx.js_emit, JsEvent::Blocked {
					ip: peer_ip.to_string(),
					reason: reason.as_str().to_string(),
					listener: ctx.listener_addr.clone(),
					ja3: peek_info.ja3.clone(),
					ja4: peek_info.ja4.clone(),
				});
				return;
			}
			// Allowlisted: active counter was not incremented; guard must not call release().
			crate::protection::Decision::AllowBypassed => false,
			crate::protection::Decision::Allow => true,
		}
	} else {
		false
	};

	// ── Connection is allowed — track it ─────────────────────────────────────
	ctx.listener_metrics.inc_active();
	ctx.global_metrics.inc_active();

	// RAII: decrement counts on scope exit.
	// Pass protection only when the active counter was incremented so release() is correct.
	let _active_guard = ActiveGuard {
		global: ctx.global_metrics.clone(),
		listener: ctx.listener_metrics.clone(),
		protection: if protection_counted { ctx.protection.clone() } else { None },
		peer_ip,
	};

	// ── 3. Route lookup ───────────────────────────────────────────────────────
	let table = ctx.route_table.0.load();
	let sni_str = peek_info.sni.as_deref();
	let route = match table.resolve(sni_str) {
		Some(r) => r.clone(),
		None => {
			ctx.listener_metrics.inc_error();
			return; // No route and no default — drop
		}
	};

	// ── 3b. Per-route rate limit ──────────────────────────────────────────────
	if let Some(rl) = &route.rate_limiter {
		if !rl.try_acquire() {
			ctx.listener_metrics.inc_error();
			return;
		}
	}

	// ── 4. Suspended route handling ───────────────────────────────────────────
	let effective_route: EffectiveRoute = if route.suspended {
		ctx.global_metrics.inc_suspended();
		let (id, rx) = ctx.suspended_registry.register();

		emit(&ctx.js_emit, JsEvent::Suspended {
			id: id.to_string(),
			sni: sni_str.unwrap_or("").to_string(),
			peer_ip: peer_ip.to_string(),
			peer_port: peer_addr.port(),
			listener: ctx.listener_addr.clone(),
		});

		let resolved = match timeout(route.suspend_timeout, rx).await {
			Ok(Ok(Some(r))) => r,
			_ => {
				ctx.suspended_registry.remove(id);
				ctx.global_metrics.dec_suspended();
				return; // Timed out or rejected
			}
		};

		ctx.global_metrics.dec_suspended();

		EffectiveRoute {
			destination: resolved.destination,
			tls_config: resolved.tls_config,
			terminate_tls: resolved.terminate_tls,
			source_address_mode: resolved.source_address_mode,
		}
	} else {
		EffectiveRoute {
			destination: route.destination.clone(),
			tls_config: route.tls_config.clone(),
			terminate_tls: route.terminate_tls,
			source_address_mode: route.source_address_mode,
		}
	};

	// ── 5. TLS handshake ──────────────────────────────────────────────────────
	let cfg = ctx.protection.as_ref().map(|p| p.config.load());
	let hs_timeout = cfg
		.as_ref()
		.map(|c| c.tls_handshake_timeout())
		.unwrap_or(Duration::from_secs(10));

	let source_mode = effective_route.source_address_mode;
	let upstream_result = if effective_route.terminate_tls {
		if let Some(tls_cfg) = effective_route.tls_config {
			let acceptor = TlsAcceptor::from(tls_cfg);
			match timeout(hs_timeout, acceptor.accept(stream)).await {
				Ok(Ok(tls_stream)) => proxy_via_tls(tls_stream, &effective_route.destination, peer_addr, source_mode, &ctx).await,
				Ok(Err(e)) => {
					tracing::debug!("TLS handshake error from {peer_ip}: {e}");
					ctx.listener_metrics.inc_error();
					return;
				}
				Err(_) => {
					tracing::debug!("TLS handshake timeout from {peer_ip}");
					ctx.listener_metrics.inc_error();
					return;
				}
			}
		} else {
			ctx.listener_metrics.inc_error();
			return;
		}
	} else {
		// Passthrough — proxy raw TCP
		proxy_raw(stream, &effective_route.destination, peer_addr, source_mode, &ctx).await
	};

	if upstream_result.is_err() {
		ctx.listener_metrics.inc_error();
	}
}

// ── Proxy helpers ─────────────────────────────────────────────────────────────

async fn proxy_via_tls(
	mut client: tokio_rustls::server::TlsStream<TcpStream>,
	dest: &Destination,
	peer_addr: SocketAddr,
	source_mode: SourceAddressMode,
	ctx: &ConnContext,
) -> std::io::Result<()> {
	let mut upstream = upstream::connect(dest, Some(peer_addr.ip()), ctx.upstream_connect_timeout)
		.await
		.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

	match &mut upstream {
		UpstreamStream::Tcp(ref mut up) => {
			apply_source_header(&mut client, up, peer_addr, source_mode).await?;
			copy_with_idle_timeout(ctx.idle_timeout, &mut client, up).await
		}
		UpstreamStream::Uds { ref mut stream, .. } => {
			apply_source_header(&mut client, stream, peer_addr, source_mode).await?;
			copy_with_idle_timeout(ctx.idle_timeout, &mut client, stream).await
		}
	}
}

async fn proxy_raw(
	mut client: TcpStream,
	dest: &Destination,
	peer_addr: SocketAddr,
	source_mode: SourceAddressMode,
	ctx: &ConnContext,
) -> std::io::Result<()> {
	let mut upstream = upstream::connect(dest, Some(peer_addr.ip()), ctx.upstream_connect_timeout)
		.await
		.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

	match &mut upstream {
		UpstreamStream::Tcp(ref mut up) => {
			apply_source_header(&mut client, up, peer_addr, source_mode).await?;
			copy_with_idle_timeout(ctx.idle_timeout, &mut client, up).await
		}
		UpstreamStream::Uds { ref mut stream, .. } => {
			apply_source_header(&mut client, stream, peer_addr, source_mode).await?;
			copy_with_idle_timeout(ctx.idle_timeout, &mut client, stream).await
		}
	}
}

/// Bidirectional copy with an optional idle timeout.
/// A zero `idle` means no timeout.
async fn copy_with_idle_timeout<A, B>(idle: Duration, a: &mut A, b: &mut B) -> std::io::Result<()>
where
	A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
	B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
	if idle.is_zero() {
		copy_bidirectional(a, b).await.map(|_| ())
	} else {
		timeout(idle, copy_bidirectional(a, b))
			.await
			.map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "idle timeout"))?
			.map(|_| ())
	}
}

/// Apply the configured source address forwarding before bidirectional copy.
async fn apply_source_header<C, U>(
	client: &mut C,
	upstream: &mut U,
	peer_addr: SocketAddr,
	mode: SourceAddressMode,
) -> std::io::Result<()>
where
	C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
	U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
	match mode {
		SourceAddressMode::None => Ok(()),
		SourceAddressMode::ProxyProtocol => {
			upstream::write_proxy_v1_header(upstream, peer_addr).await
		}
		SourceAddressMode::XForwardedFor => {
			upstream::inject_x_forwarded_for(client, upstream, peer_addr).await
		}
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

struct EffectiveRoute {
	destination: Destination,
	tls_config: Option<Arc<rustls::ServerConfig>>,
	terminate_tls: bool,
	source_address_mode: SourceAddressMode,
}

struct ActiveGuard {
	global: Arc<GlobalMetrics>,
	listener: Arc<ListenerMetrics>,
	protection: Option<Arc<ProtectionState>>,
	peer_ip: IpAddr,
}

impl Drop for ActiveGuard {
	fn drop(&mut self) {
		self.global.dec_active();
		self.listener.dec_active();
		if let Some(p) = &self.protection {
			p.release(self.peer_ip);
		}
	}
}

fn emit(tsf: &ThreadsafeFunction<JsEvent>, event: JsEvent) {
	// Non-blocking — drop the event if the JS queue is full
	tsf.call(Ok(event), napi::threadsafe_function::ThreadsafeFunctionCallMode::NonBlocking);
}
