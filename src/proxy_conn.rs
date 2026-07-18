use crate::metrics::{GlobalMetrics, ListenerMetrics};
use crate::protection::ProtectionState;
use crate::router::{Destination, ForwardFingerprint, LiveRouteTable, SourceAddressMode};
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
	// The address the client connected to — the PROXY v2 destination. Captured before the
	// stream is consumed by the TLS handshake.
	let local_addr = stream.local_addr().ok();

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
			// resolveConnection() supplies a single destination; no h2 split.
			destination_h2: None,
			tls_config: resolved.tls_config,
			terminate_tls: resolved.terminate_tls,
			source_address_mode: resolved.source_address_mode,
			forward_fingerprint: resolved.forward_fingerprint,
		}
	} else {
		EffectiveRoute {
			destination: route.destination.clone(),
			destination_h2: route.destination_h2.clone(),
			tls_config: route.tls_config.clone(),
			terminate_tls: route.terminate_tls,
			source_address_mode: route.source_address_mode,
			forward_fingerprint: route.forward_fingerprint,
		}
	};

	// ── 5. TLS handshake ──────────────────────────────────────────────────────
	let cfg = ctx.protection.as_ref().map(|p| p.config.load());
	let hs_timeout = cfg
		.as_ref()
		.map(|c| c.tls_handshake_timeout())
		.unwrap_or(Duration::from_secs(10));

	let sf = SourceForwarding {
		mode: effective_route.source_address_mode,
		fingerprint: effective_route.forward_fingerprint,
		ja3: &peek_info.ja3,
		ja4: &peek_info.ja4,
		sni: sni_str,
		tls: None,
		peer_addr,
		local_addr,
	};
	let upstream_result = if effective_route.terminate_tls {
		if let Some(tls_cfg) = effective_route.tls_config {
			let acceptor = TlsAcceptor::from(tls_cfg);
			match timeout(hs_timeout, acceptor.accept(stream)).await {
				Ok(Ok(tls_stream)) => {
					// Route by negotiated protocol: h2 connections go to the route's
					// h2-marked upstreams (e.g. Harper's `-h2.sock` mirror) when present.
					let negotiated_h2 = tls_stream.get_ref().1.alpn_protocol() == Some(b"h2");
					let destination = match &effective_route.destination_h2 {
						Some(dest) if negotiated_h2 => dest,
						_ => &effective_route.destination,
					};
					// Header injection (XFF / X-JA3) never touches an h2 stream: forward()
					// gates it on the negotiated protocol (l7_http1), covering static and
					// suspended-route configs alike.
					proxy_via_tls(tls_stream, destination, sf, &ctx).await
				}
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
		proxy_raw(stream, &effective_route.destination, sf, &ctx).await
	};

	if upstream_result.is_err() {
		ctx.listener_metrics.inc_error();
	}
}

// ── Proxy helpers ─────────────────────────────────────────────────────────────

async fn proxy_via_tls(
	mut client: tokio_rustls::server::TlsStream<TcpStream>,
	dest: &Destination,
	sf: SourceForwarding<'_>,
	ctx: &ConnContext,
) -> std::io::Result<()> {
	// TLS facts (incl. the verified mTLS client cert chain) forwarded via PROXY v2
	// TLVs; only collected on routes that can carry them.
	let tls_forward = matches!(sf.mode, SourceAddressMode::ProxyProtocolV2)
		.then(|| collect_tls_forward(client.get_ref().1));
	let sf = SourceForwarding { tls: tls_forward.as_ref(), ..sf };

	let mut upstream = upstream::connect(dest, Some(sf.peer_addr.ip()), ctx.upstream_connect_timeout)
		.await
		.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

	// HTTP-header injection is only valid for a plaintext HTTP/1 upstream. An h2-negotiated
	// upstream receives binary frames, so text header insertion would corrupt them.
	let l7_http1 = client.get_ref().1.alpn_protocol() != Some(b"h2".as_ref());

	match &mut upstream {
		UpstreamStream::Tcp(ref mut up) => forward(&mut client, up, &sf, l7_http1, ctx.idle_timeout).await,
		UpstreamStream::Uds { ref mut stream, .. } => {
			forward(&mut client, stream, &sf, l7_http1, ctx.idle_timeout).await
		}
	}
}

async fn proxy_raw(
	mut client: TcpStream,
	dest: &Destination,
	sf: SourceForwarding<'_>,
	ctx: &ConnContext,
) -> std::io::Result<()> {
	let mut upstream = upstream::connect(dest, Some(sf.peer_addr.ip()), ctx.upstream_connect_timeout)
		.await
		.map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?;

	// Passthrough forwards raw TLS bytes — never a plaintext HTTP/1 stream, so header injection
	// is disabled (only PROXY protocol carriers apply here).
	match &mut upstream {
		UpstreamStream::Tcp(ref mut up) => forward(&mut client, up, &sf, false, ctx.idle_timeout).await,
		UpstreamStream::Uds { ref mut stream, .. } => {
			forward(&mut client, stream, &sf, false, ctx.idle_timeout).await
		}
	}
}

/// Write the configured source-address prefix (PROXY v1/v2 header) to the upstream, then copy
/// bidirectionally under the idle timeout. On an HTTP/1 injection route the client→upstream half
/// is the per-request header rewriter (finding fixes: the header read now lives inside the idle
/// timeout, and every request — fragmented, pipelined, or keep-alive — is stripped and rewritten,
/// not just the first read).
async fn forward<C, U>(
	client: &mut C,
	upstream: &mut U,
	sf: &SourceForwarding<'_>,
	l7_http1: bool,
	idle: Duration,
) -> std::io::Result<()>
where
	C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
	U: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
	let body = async {
		write_connection_prefix(upstream, sf).await?;
		let rewrites = header_rewrites(sf, l7_http1);
		if rewrites.is_empty() {
			copy_bidirectional(client, upstream).await.map(|_| ())
		} else {
			crate::http_proxy::proxy_http1_rewriting(client, upstream, &rewrites).await
		}
	};
	if idle.is_zero() {
		body.await
	} else {
		timeout(idle, body)
			.await
			.map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "idle timeout"))?
	}
}

/// Per-connection source-address + fingerprint forwarding parameters. All fields are `Copy`
/// (`ja3`/`ja4` borrow the connection's `PeekInfo`), so the struct is passed by value.
#[derive(Clone, Copy)]
struct SourceForwarding<'a> {
	mode: SourceAddressMode,
	fingerprint: ForwardFingerprint,
	ja3: &'a str,
	ja4: &'a str,
	/// SNI from the ClientHello, forwarded as PP2_TYPE_AUTHORITY.
	sni: Option<&'a str>,
	/// TLS facts from termination (set by proxy_via_tls on PROXY v2 routes).
	tls: Option<&'a TlsForward>,
	peer_addr: SocketAddr,
	local_addr: Option<SocketAddr>,
}

/// TLS facts captured after termination, forwarded via PROXY v2 TLVs.
struct TlsForward {
	version: Option<&'static str>,
	cipher: Option<String>,
	alpn: Option<Vec<u8>>,
	/// Client certificate chain (DER, leaf first). Non-empty only when the client
	/// presented a certificate and the route's verifier accepted it — rustls aborts
	/// the handshake otherwise, so presence implies verification.
	client_cert_chain: Vec<Vec<u8>>,
}

/// PP2_TYPE_SSL value: client(1) verify(4 BE) sub-TLVs (version, cipher).
/// Per spec, verify is zero only when the client presented a certificate AND it
/// was successfully verified — rustls only completes the handshake when the
/// configured verifier accepted the cert, so cert presence implies verified.
fn build_ssl_tlv(tls: &TlsForward) -> Vec<u8> {
	let has_cert = !tls.client_cert_chain.is_empty();
	let mut ssl: Vec<u8> = Vec::with_capacity(32);
	ssl.push(upstream::PP2_CLIENT_SSL | if has_cert { upstream::PP2_CLIENT_CERT_CONN } else { 0 });
	ssl.extend_from_slice(&if has_cert { 0u32 } else { 1u32 }.to_be_bytes());
	if let Some(version) = tls.version {
		push_sub_tlv(&mut ssl, upstream::PP2_SUBTYPE_SSL_VERSION, version.as_bytes());
	}
	if let Some(cipher) = &tls.cipher {
		push_sub_tlv(&mut ssl, upstream::PP2_SUBTYPE_SSL_CIPHER, cipher.as_bytes());
	}
	ssl
}

fn push_sub_tlv(buf: &mut Vec<u8>, ty: u8, value: &[u8]) {
	buf.push(ty);
	buf.extend_from_slice(&(value.len() as u16).to_be_bytes());
	buf.extend_from_slice(value);
}

fn collect_tls_forward(conn: &rustls::ServerConnection) -> TlsForward {
	TlsForward {
		version: match conn.protocol_version() {
			Some(rustls::ProtocolVersion::TLSv1_3) => Some("TLSv1.3"),
			Some(rustls::ProtocolVersion::TLSv1_2) => Some("TLSv1.2"),
			_ => None,
		},
		cipher: conn.negotiated_cipher_suite().map(|s| format!("{:?}", s.suite())),
		alpn: conn.alpn_protocol().map(|p| p.to_vec()),
		client_cert_chain: conn
			.peer_certificates()
			.map(|certs| certs.iter().map(|c| c.as_ref().to_vec()).collect())
			.unwrap_or_default(),
	}
}

impl SourceForwarding<'_> {
	/// The fingerprint string selected for forwarding ("" when none, or unparsed).
	fn fingerprint_value(&self) -> &str {
		match self.fingerprint {
			ForwardFingerprint::None => "",
			ForwardFingerprint::Ja3 => self.ja3,
			ForwardFingerprint::Ja4 => self.ja4,
		}
	}

	/// The HTTP header name symphony owns for the configured fingerprint mode, if any.
	fn fingerprint_header_name(&self) -> Option<&'static str> {
		match self.fingerprint {
			ForwardFingerprint::Ja3 => Some("X-JA3"),
			ForwardFingerprint::Ja4 => Some("X-JA4"),
			ForwardFingerprint::None => None,
		}
	}
}

/// Write the one-shot connection prefix (PROXY v1/v2 header) the mode calls for. HTTP-header
/// carriers have no prefix — they rewrite the request stream instead (see `header_rewrites`).
async fn write_connection_prefix<U>(upstream: &mut U, sf: &SourceForwarding<'_>) -> std::io::Result<()>
where
	U: tokio::io::AsyncWrite + Unpin,
{
	match sf.mode {
		SourceAddressMode::None | SourceAddressMode::XForwardedFor => Ok(()),
		SourceAddressMode::ProxyProtocol => upstream::write_proxy_v1_header(upstream, sf.peer_addr).await,
		SourceAddressMode::ProxyProtocolV2 => {
			let value = sf.fingerprint_value();
			let mut tlvs: Vec<(u8, &[u8])> = Vec::new();
			match sf.fingerprint {
				ForwardFingerprint::Ja3 => tlvs.push((upstream::PP2_TYPE_JA3, value.as_bytes())),
				ForwardFingerprint::Ja4 => tlvs.push((upstream::PP2_TYPE_JA4, value.as_bytes())),
				ForwardFingerprint::None => {}
			}
			if let Some(sni) = sf.sni {
				tlvs.push((upstream::PP2_TYPE_AUTHORITY, sni.as_bytes()));
			}
			// Built outside the branch so the borrow in `tlvs` outlives the write call.
			let ssl_tlv;
			if let Some(tls) = sf.tls {
				if let Some(alpn) = &tls.alpn {
					tlvs.push((upstream::PP2_TYPE_ALPN, alpn));
				}
				ssl_tlv = build_ssl_tlv(tls);
				tlvs.push((upstream::PP2_TYPE_SSL, &ssl_tlv));
				// The v2 header length field is u16: a pathological chain that can't fit
				// is dropped (the SSL TLV still signals a verified cert was presented)
				// rather than failing the connection.
				let chain_len: usize = tls.client_cert_chain.iter().map(|c| 3 + c.len()).sum();
				let tlv_len: usize = tlvs.iter().map(|(_, v)| 3 + v.len()).sum();
				if tlv_len + chain_len + 36 <= u16::MAX as usize
					&& tls.client_cert_chain.iter().all(|c| c.len() <= u16::MAX as usize)
				{
					for cert in &tls.client_cert_chain {
						tlvs.push((upstream::PP2_TYPE_CLIENT_CERT, cert));
					}
				} else if chain_len > 0 {
					tracing::warn!(
						"client cert chain too large for PROXY v2 header ({chain_len} bytes); omitting chain TLVs"
					);
				}
			}
			upstream::write_proxy_v2_header(upstream, sf.peer_addr, sf.local_addr, &tlvs).await
		}
	}
}

/// The set of headers symphony owns end-to-end on the client→upstream request stream, applied to
/// every HTTP/1 request. Empty (→ a plain copy, no rewriting) unless the upstream is a plaintext
/// HTTP/1 stream and the mode injects HTTP headers.
///
/// A configured header is *always* stripped from the client's request, even when symphony has no
/// authoritative value to substitute (`value: None`) — a client must never smuggle its own
/// `X-JA3`/`X-JA4`/`X-Forwarded-For` through precisely when we can't replace it. PROXY v2 carries
/// the fingerprint in a TLV, so it adds no header rewrite.
fn header_rewrites(sf: &SourceForwarding<'_>, l7_http1: bool) -> Vec<crate::http_proxy::HeaderRewrite> {
	use crate::http_proxy::HeaderRewrite;
	if !l7_http1 {
		return Vec::new();
	}
	let mut rewrites: Vec<HeaderRewrite> = Vec::new();
	if matches!(sf.mode, SourceAddressMode::XForwardedFor) {
		rewrites.push(HeaderRewrite {
			name: "X-Forwarded-For",
			value: Some(sf.peer_addr.ip().to_string()),
		});
	}
	// The fingerprint header rides every HTTP-header mode (None/v1/XFF); v2 uses a TLV instead.
	if !matches!(sf.mode, SourceAddressMode::ProxyProtocolV2) {
		if let Some(name) = sf.fingerprint_header_name() {
			let value = sf.fingerprint_value();
			rewrites.push(HeaderRewrite {
				name,
				value: (!value.is_empty()).then(|| value.to_string()),
			});
		}
	}
	rewrites
}

// ── Helpers ───────────────────────────────────────────────────────────────────

struct EffectiveRoute {
	destination: Destination,
	/// Destination for ALPN-h2 connections, when the route has h2-marked upstreams.
	destination_h2: Option<Destination>,
	tls_config: Option<Arc<rustls::ServerConfig>>,
	terminate_tls: bool,
	source_address_mode: SourceAddressMode,
	forward_fingerprint: ForwardFingerprint,
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
