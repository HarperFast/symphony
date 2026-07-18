use crate::http_listener::spawn_http_listeners;
use crate::listener::spawn_listeners;
use crate::metrics::{GlobalMetrics, ListenerMetrics};
use crate::protection::ProtectionState;
use crate::proxy_conn::{ConnContext, JsEvent};
use crate::router::{
	build_route_table, ListenerTlsSpec, LiveRouteTable, RouteSpec, SourceAddressMode, UpstreamSpec,
};
use crate::suspended::{build_resolved_route, ResolveSpec, ResolveUpstream, SuspendedRegistry};
use ipnetwork::IpNetwork;
use napi::bindgen_prelude::*;
use napi::threadsafe_function::ThreadsafeFunction;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::runtime::{Handle as RtHandle, Runtime};
use tokio::sync::broadcast;

// ── JS-facing config types (in / out of NAPI boundary only) ──────────────────

#[napi(object)]
pub struct JsUpstream {
	pub kind: String,
	pub host: Option<String>,
	pub port: Option<u16>,
	pub path: Option<String>,
	pub ip_affinity: Option<bool>,
	pub ip_affinity_ttl_ms: Option<f64>,
	/// Linux process ID of the worker thread (UDS upstreams only).
	pub pid: Option<u32>,
	/// Linux thread ID of the worker thread (UDS upstreams only).
	pub tid: Option<u32>,
	/// Application protocol the upstream speaks: "h2" for cleartext HTTP/2
	/// (UDS upstreams only). Omitted = HTTP/1.x.
	pub protocol: Option<String>,
}

#[napi(object)]
pub struct JsCertConfig {
	pub cert_chain: Either<String, Buffer>,
	pub private_key: Either<String, Buffer>,
}

#[napi(object)]
pub struct JsMtlsConfig {
	pub client_ca_cert: Either<String, Buffer>,
	pub require_client_cert: Option<bool>,
}

#[napi(object)]
pub struct JsRouteConfig {
	pub sni: String,
	pub upstreams: Vec<JsUpstream>,
	pub terminate_tls: bool,
	pub cert: Option<JsCertConfig>,
	pub mtls: Option<JsMtlsConfig>,
	pub suspended: Option<bool>,
	pub suspend_timeout_ms: Option<f64>,
	/// Global rate limit for this route (new connections per second).
	/// Connections are silently dropped (RST) when the token bucket is exhausted.
	pub max_connections_per_second: Option<f64>,
	/// Token bucket burst ceiling (defaults to `maxConnectionsPerSecond`).
	pub burst: Option<f64>,
	/// How the real client IP is forwarded to the upstream.
	/// "proxyProtocol" (default for UDS), "xForwardedFor", or "none" (default for TCP).
	pub source_address_header: Option<String>,
	/// Advertise h2 in ALPN so clients can negotiate HTTP/2. Default: false.
	pub http2: Option<bool>,
}

#[napi(object)]
pub struct JsRateLimitConfig {
	pub connections_per_second: f64,
	pub burst: Option<f64>,
}

#[napi(object)]
pub struct JsProtectionConfig {
	pub rate_limit: Option<JsRateLimitConfig>,
	pub max_concurrent_per_ip: Option<u32>,
	pub allowlist: Option<Vec<String>>,
	pub blocklist: Option<Vec<String>>,
	pub ja3_blocklist: Option<Vec<String>>,
	/// JA4 fingerprints to block. Each value is the full 36-char JA4 string
	/// (t<ver><sni><cc><ec><alpn>_<12hex>_<12hex>); case-insensitive match.
	pub ja4_blocklist: Option<Vec<String>>,
	pub tls_handshake_timeout_ms: Option<f64>,
	pub require_sni: Option<bool>,
}

#[napi(object)]
pub struct JsListenerConfig {
	pub host: Option<String>,
	pub port: u16,
	/// Listener protocol: "tls" (default) or "http".
	pub mode: Option<String>,
	pub default_cert: Option<JsCertConfig>,
	pub mtls: Option<JsMtlsConfig>,
	pub max_connections: Option<u32>,
	pub idle_timeout_ms: Option<f64>,
	pub protection: Option<JsProtectionConfig>,
}

#[napi(object)]
pub struct JsProxyConfig {
	pub listeners: Vec<JsListenerConfig>,
	pub routes: Vec<JsRouteConfig>,
	pub worker_threads: Option<u32>,
	pub read_buffer_size: Option<u32>,
}

#[napi(object)]
pub struct JsHotConfig {
	pub routes: Option<Vec<JsRouteConfig>>,
}

#[napi(object)]
pub struct JsProxyMetrics {
	pub active_connections: f64,
	pub blocked_connections: f64,
	pub pending_suspended: f64,
}

#[napi(object)]
pub struct JsBlockedIpsInfo {
	pub rate_limited: Vec<String>,
	pub concurrency_limited: Vec<String>,
	pub cidr_blocklist: Vec<String>,
}

#[napi(object)]
pub struct JsResolveRoute {
	pub upstream: JsUpstream,
	pub terminate_tls: bool,
	pub cert: Option<JsCertConfig>,
	pub mtls: Option<JsMtlsConfig>,
	pub source_address_header: Option<String>,
	pub http2: Option<bool>,
}

// ── Plain Rust internal config (all Send + Sync) ──────────────────────────────

/// Listener protocol.
#[derive(Clone, Copy, Debug, PartialEq)]
enum ListenerMode {
	Tls,
	Http,
}

/// Parsed listener config stored in the struct — no napi raw pointers.
struct InternalListener {
	addr: SocketAddr,
	max_connections: u32,
	mode: ListenerMode,
}

/// Per-listener runtime state.
struct ListenerState {
	addr: String,
	metrics: Arc<ListenerMetrics>,
	protection: Option<Arc<ProtectionState>>,
	protection_blocklist: Vec<String>,
}

// ── SymphonyProxy napi class ──────────────────────────────────────────────────

#[napi]
pub struct SymphonyProxyWrap {
	// Plain-Rust config (all Send + Sync)
	listeners: Vec<InternalListener>,
	default_listener_tls: ListenerTlsSpec,
	worker_threads: usize,
	idle_timeout: Duration,
	read_buffer_size: usize,
	// Shared runtime state
	route_table: Arc<LiveRouteTable>,
	suspended_registry: Arc<SuspendedRegistry>,
	global_metrics: Arc<GlobalMetrics>,
	listener_states: Vec<ListenerState>,
	// Interior mutability for start/stop
	shutdown_tx: Mutex<Option<broadcast::Sender<()>>>,
	js_emit: Arc<ThreadsafeFunction<JsEvent>>,
	// Dedicated multi-thread runtime for all proxy I/O.
	// napi's tokio_rt runs a single-threaded executor; spawning proxy tasks there
	// would serialise all connections onto one OS thread.  By creating our own
	// multi-thread runtime and using its Handle to spawn, every accept loop and
	// connection handler gets distributed across the full CPU count.
	// Handle is Send+Sync; Runtime is Send-only, so it lives in a Mutex.
	rt: Mutex<Option<Runtime>>,
	rt_handle: RtHandle,
}

#[napi]
impl SymphonyProxyWrap {
	#[napi(constructor)]
	pub fn new(config: JsProxyConfig, emit_fn: JsFunction) -> Result<Self> {
		// Install ring as the process-level CryptoProvider for rustls 0.23.
		// When aws-lc-rs is also present as a transitive dep, rustls cannot
		// auto-select — we must choose explicitly. The `let _ =` makes this
		// idempotent (no-op if already installed by a previous call or test).
		let _ = rustls::crypto::ring::default_provider().install_default();

		// Initialise tracing subscriber (honours RUST_LOG). Idempotent.
		let _ = tracing_subscriber::fmt()
			.with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
			.try_init();

		// ── Convert all napi types to plain Rust before storing ───────────────
		// Use the first TLS-mode listener as the source for fallback cert/mTLS.
		// HTTP-mode listeners don't carry TLS config.
		let default_listener_tls = config
			.listeners
			.iter()
			.find(|l| !matches!(l.mode.as_deref(), Some("http")))
			.map(listener_tls_spec)
			.unwrap_or_else(ListenerTlsSpec::empty);

		let worker_threads = config.worker_threads.unwrap_or(num_cpus()) as usize;
		// 0 means "no idle timeout" — stored as Duration::ZERO and checked in proxy_conn.rs.
		let idle_timeout_ms = config
			.listeners
			.first()
			.and_then(|l| l.idle_timeout_ms)
			.unwrap_or(60_000.0);
		let idle_timeout = if idle_timeout_ms > 0.0 {
			Duration::from_millis(idle_timeout_ms as u64)
		} else {
			Duration::ZERO
		};
		let read_buffer_size = config.read_buffer_size.unwrap_or(65_536) as usize;

		let mut internal_listeners = Vec::new();
		let mut listener_states = Vec::new();

		for l in &config.listeners {
			let host = l.host.as_deref().unwrap_or("0.0.0.0");
			let addr_str = format!("{}:{}", host, l.port);
			let addr: SocketAddr = addr_str
				.parse()
				.map_err(|e| napi::Error::from_reason(format!("invalid listener address '{addr_str}': {e}")))?;

			let mode = match l.mode.as_deref() {
				None | Some("tls") => ListenerMode::Tls,
				Some("http") => ListenerMode::Http,
				Some(other) => {
					return Err(napi::Error::from_reason(format!(
						"unknown listener mode '{other}'; expected 'tls' or 'http'"
					)))
				}
			};

			internal_listeners.push(InternalListener {
				addr,
				max_connections: l.max_connections.unwrap_or(0),
				mode,
			});

			let (protection, protection_blocklist) = if let Some(prot_cfg) = &l.protection {
				let (cfg, allowlist, blocklist, bl_strings) = parse_protection_config(prot_cfg)?;
				let state = ProtectionState::new(cfg, allowlist, blocklist);
				(Some(state), bl_strings)
			} else {
				(None, Vec::new())
			};

			listener_states.push(ListenerState {
				addr: addr_str,
				metrics: Arc::new(ListenerMetrics::default()),
				protection,
				protection_blocklist,
			});
		}

		// Build initial route table
		let specs: Vec<RouteSpec> = config
			.routes
			.iter()
			.map(parse_route_spec)
			.collect::<Result<Vec<_>>>()?;
		let table = build_route_table(&specs, &default_listener_tls, None)
			.map_err(|e| napi::Error::from_reason(e.to_string()))?;

		// Set up threadsafe event emitter
		let js_emit: ThreadsafeFunction<JsEvent> = emit_fn
			.create_threadsafe_function(128, |ctx| {
				let event: JsEvent = ctx.value;
				let env = ctx.env;
				let mut obj = env.create_object()?;
				match event {
					JsEvent::Blocked { ip, reason, listener, ja3, ja4 } => {
						obj.set("type", "blocked")?;
						obj.set("ip", ip)?;
						obj.set("reason", reason)?;
						obj.set("listener", listener)?;
						obj.set("ja3", ja3)?;
						obj.set("ja4", ja4)?;
					}
					JsEvent::Suspended { id, sni, peer_ip, peer_port, listener } => {
						obj.set("type", "suspended")?;
						obj.set("id", id)?;
						obj.set("sni", sni)?;
						obj.set("peerIp", peer_ip)?;
						obj.set("peerPort", peer_port as f64)?;
						obj.set("listener", listener)?;
					}
					JsEvent::Error { message, listener } => {
						obj.set("type", "error")?;
						obj.set("message", message)?;
						obj.set("listener", listener)?;
					}
				}
				Ok(vec![obj])
			})?;

		// Build a dedicated multi-thread runtime for all proxy I/O work.
		let rt = tokio::runtime::Builder::new_multi_thread()
			.worker_threads(worker_threads)
			.enable_all()
			.build()
			.map_err(|e| napi::Error::from_reason(format!("failed to create proxy runtime: {e}")))?;
		let rt_handle = rt.handle().clone();

		Ok(Self {
			listeners: internal_listeners,
			default_listener_tls,
			worker_threads,
			idle_timeout,
			read_buffer_size,
			route_table: Arc::new(LiveRouteTable(arc_swap::ArcSwap::new(Arc::new(table)))),
			suspended_registry: SuspendedRegistry::new(),
			global_metrics: Arc::new(GlobalMetrics::default()),
			listener_states,
			shutdown_tx: Mutex::new(None),
			js_emit: Arc::new(js_emit),
			rt: Mutex::new(Some(rt)),
			rt_handle,
		})
	}

	#[napi]
	pub async fn start(&self) -> Result<()> {
		let (tx, _) = broadcast::channel(1);
		*self.shutdown_tx.lock().unwrap() = Some(tx.clone());

		for (i, listener) in self.listeners.iter().enumerate() {
			let state = &self.listener_states[i];
			// Use the TLS handshake timeout as the upstream connect timeout when
			// protection is configured; otherwise fall back to 30 s.
			let upstream_connect_timeout = state
				.protection
				.as_ref()
				.map(|p| p.config.load().tls_handshake_timeout())
				.unwrap_or(std::time::Duration::from_secs(30));

			let ctx = Arc::new(ConnContext {
				route_table: self.route_table.clone(),
				protection: state.protection.clone(),
				suspended_registry: self.suspended_registry.clone(),
				global_metrics: self.global_metrics.clone(),
				listener_metrics: state.metrics.clone(),
				listener_addr: state.addr.clone(),
				idle_timeout: self.idle_timeout,
				upstream_connect_timeout,
				read_buffer_size: self.read_buffer_size,
				js_emit: self.js_emit.clone(),
			});

			let max_conn = listener.max_connections;
			let workers = self.worker_threads;
			let addr = listener.addr;
			let mode = listener.mode;
			let rx = tx.subscribe();

			self.rt_handle.spawn(async move {
				let result = match mode {
					ListenerMode::Tls => spawn_listeners(addr, workers, max_conn, ctx, rx).await,
					ListenerMode::Http => spawn_http_listeners(addr, workers, max_conn, ctx, rx).await,
				};
				if let Err(e) = result {
					tracing::error!("listener {addr} failed: {e}");
				}
			});
		}

		// Spawn a background task that samples /proc/{pid}/task/{tid}/stat every
		// 250 ms for UDS upstreams that have pid/tid configured.  This is a no-op
		// loop iteration when no routes have such upstreams.
		let monitor_table = self.route_table.clone();
		let mut monitor_rx = tx.subscribe();
		self.rt_handle.spawn(async move {
			let interval = Duration::from_millis(250);
			loop {
				tokio::select! {
					_ = monitor_rx.recv() => break,
					_ = tokio::time::sleep(interval) => {
						let table = monitor_table.0.load();
						for balancer in &table.monitored_balancers {
							balancer.update_cpu_stats();
						}
					}
				}
			}
		});

		Ok(())
	}

	#[napi]
	pub async fn stop(&self, timeout_ms: Option<f64>) -> Result<()> {
		if let Some(tx) = self.shutdown_tx.lock().unwrap().take() {
			let _ = tx.send(());
		}
		let ms = timeout_ms.unwrap_or(100.0).min(5_000.0) as u64;
		tokio::time::sleep(Duration::from_millis(ms)).await;
		Ok(())
	}

	#[napi]
	pub fn update_config(&self, hot: JsHotConfig) -> Result<()> {
		if let Some(routes) = hot.routes {
			let specs: Vec<RouteSpec> = routes
				.iter()
				.map(parse_route_spec)
				.collect::<Result<Vec<_>>>()?;
			// Pass the currently-live table so a route whose cert transiently fails to
			// rebuild (mid-rotation KeyMismatch) retains its last-good cert instead of
			// dropping the SNI from the live table.
			let current = self.route_table.0.load();
			let table = build_route_table(&specs, &self.default_listener_tls, Some(&current))
				.map_err(|e| napi::Error::from_reason(e.to_string()))?;
			self.route_table.swap(table);
		}
		Ok(())
	}

	#[napi]
	pub fn metrics(&self) -> JsProxyMetrics {
		JsProxyMetrics {
			active_connections: self.global_metrics.active_connections.load(Ordering::Relaxed) as f64,
			blocked_connections: self.global_metrics.total_blocked.load(Ordering::Relaxed) as f64,
			pending_suspended: self.global_metrics.pending_suspended.load(Ordering::Relaxed) as f64,
		}
	}

	#[napi]
	pub fn blocked_ips(&self) -> JsBlockedIpsInfo {
		let mut rate_limited: Vec<String> = Vec::new();
		let mut concurrency_limited: Vec<String> = Vec::new();
		let mut cidr_blocklist: Vec<String> = Vec::new();

		for state in &self.listener_states {
			for bl in &state.protection_blocklist {
				if !cidr_blocklist.contains(bl) {
					cidr_blocklist.push(bl.clone());
				}
			}
			if let Some(prot) = &state.protection {
				let cfg = prot.config.load();
				let max = cfg.max_concurrent_per_ip;
				let (rl, cl) = prot.blocked_ips(max);
				for ip in rl {
					let s = ip.to_string();
					if !rate_limited.contains(&s) {
						rate_limited.push(s);
					}
				}
				for ip in cl {
					let s = ip.to_string();
					if !concurrency_limited.contains(&s) {
						concurrency_limited.push(s);
					}
				}
			}
		}

		JsBlockedIpsInfo { rate_limited, concurrency_limited, cidr_blocklist }
	}

	#[napi]
	pub fn resolve_connection(&self, id: String, route: Option<JsResolveRoute>) -> Result<()> {
		let id_num: u64 = id
			.parse()
			.map_err(|_| napi::Error::from_reason(format!("invalid connection id: {id}")))?;

		let resolved = match route {
			None => None,
			Some(r) => {
				let spec = parse_resolve_spec(&r)?;
				Some(
					build_resolved_route(&spec)
						.map_err(|e| napi::Error::from_reason(e.to_string()))?,
				)
			}
		};

		self.suspended_registry.resolve(id_num, resolved);
		Ok(())
	}
}

// ── Config parsing helpers ────────────────────────────────────────────────────

fn parse_route_spec(r: &JsRouteConfig) -> Result<RouteSpec> {
	let upstreams: Vec<UpstreamSpec> = r
		.upstreams
		.iter()
		.map(|u| parse_upstream_spec(u, &r.sni))
		.collect::<Result<Vec<_>>>()?;

	let has_uds = upstreams.iter().any(|u| matches!(u, UpstreamSpec::Uds { .. }));
	let source_address_mode = parse_source_address_mode(r.source_address_header.as_deref(), has_uds)?;

	let result = Ok(RouteSpec {
		sni: r.sni.clone(),
		upstreams,
		terminate_tls: r.terminate_tls,
		cert_pem: r.cert.as_ref().map(|c| pem_bytes(&c.cert_chain)),
		key_pem: r.cert.as_ref().map(|c| pem_bytes(&c.private_key)),
		mtls_ca_pem: r.mtls.as_ref().map(|m| pem_bytes(&m.client_ca_cert)),
		require_client_cert: r.mtls.as_ref().and_then(|m| m.require_client_cert).unwrap_or(false),
		suspended: r.suspended.unwrap_or(false),
		suspend_timeout_ms: r.suspend_timeout_ms.unwrap_or(30_000.0) as u64,
		max_cps: r.max_connections_per_second,
		burst: r.burst,
		source_address_mode,
		http2: r.http2.unwrap_or(false),
	});

	if let Ok(ref spec) = result {
		if spec.http2 && !spec.terminate_tls {
			eprintln!("symphony: route '{}': http2=true has no effect when terminateTls=false (passthrough mode)", spec.sni);
		}
	}
	result
}

fn parse_upstream_spec(u: &JsUpstream, sni: &str) -> Result<UpstreamSpec> {
	match u.kind.as_str() {
		"tcp" => {
			let host = u
				.host
				.clone()
				.ok_or_else(|| napi::Error::from_reason(format!("tcp upstream for '{sni}' missing host")))?;
			let port = u
				.port
				.ok_or_else(|| napi::Error::from_reason(format!("tcp upstream for '{sni}' missing port")))?;
			if u.protocol.is_some() {
				return Err(napi::Error::from_reason(format!(
					"tcp upstream for '{sni}': 'protocol' is only supported on uds upstreams"
				)));
			}
			Ok(UpstreamSpec::Tcp { host, port })
		}
		"uds" => {
			let path = u
				.path
				.clone()
				.ok_or_else(|| napi::Error::from_reason(format!("uds upstream for '{sni}' missing path")))?;
			if let Some(p) = &u.protocol {
				if p != "h2" && p != "http/1.1" {
					return Err(napi::Error::from_reason(format!(
						"uds upstream for '{sni}': unknown protocol '{p}' (expected 'h2' or 'http/1.1')"
					)));
				}
			}
			Ok(UpstreamSpec::Uds {
				paths: vec![path],
				pids: vec![u.pid],
				tids: vec![u.tid],
				ip_affinity: u.ip_affinity.unwrap_or(false),
				affinity_ttl_ms: u.ip_affinity_ttl_ms.unwrap_or(300_000.0) as u64,
				protocol: u.protocol.clone().filter(|p| p == "h2"),
			})
		}
		other => Err(napi::Error::from_reason(format!(
			"unknown upstream kind '{other}' for sni '{sni}'"
		))),
	}
}

fn parse_resolve_spec(r: &JsResolveRoute) -> Result<ResolveSpec> {
	let upstream = match parse_upstream_spec(&r.upstream, "<resolved>")? {
		UpstreamSpec::Tcp { host, port } => {
			let addr = format!("{host}:{port}")
				.parse()
				.map_err(|e| napi::Error::from_reason(format!("invalid address: {e}")))?;
			ResolveUpstream::Tcp(addr)
		}
		UpstreamSpec::Uds { paths, ip_affinity, affinity_ttl_ms, .. } => {
			ResolveUpstream::Uds { paths, ip_affinity, affinity_ttl_ms }
		}
	};

	let has_uds = matches!(&upstream, ResolveUpstream::Uds { .. });
	let source_address_mode = parse_source_address_mode(r.source_address_header.as_deref(), has_uds)?;

	Ok(ResolveSpec {
		upstream,
		terminate_tls: r.terminate_tls,
		cert_pem: r.cert.as_ref().map(|c| pem_bytes(&c.cert_chain)),
		key_pem: r.cert.as_ref().map(|c| pem_bytes(&c.private_key)),
		mtls_ca_pem: r.mtls.as_ref().map(|m| pem_bytes(&m.client_ca_cert)),
		require_client_cert: r.mtls.as_ref().and_then(|m| m.require_client_cert).unwrap_or(false),
		source_address_mode,
		http2: r.http2.unwrap_or(false),
	})
}

fn parse_protection_config(
	prot: &JsProtectionConfig,
) -> Result<(
	crate::protection::ProtectionConfig,
	Vec<IpNetwork>,
	Vec<IpNetwork>,
	Vec<String>,
)> {
	let mut cfg = crate::protection::ProtectionConfig::default();

	if let Some(rl) = &prot.rate_limit {
		cfg.rate_limit_cps = Some(rl.connections_per_second);
		cfg.rate_limit_burst = rl.burst;
	}
	cfg.max_concurrent_per_ip = prot.max_concurrent_per_ip.unwrap_or(0);

	if let Some(ja3s) = &prot.ja3_blocklist {
		for hex in ja3s {
			if let Some(bytes) = hex_to_bytes16(hex) {
				cfg.ja3_blocklist.insert(bytes);
			}
		}
	}

	if let Some(ja4s) = &prot.ja4_blocklist {
		for s in ja4s {
			// Normalize to lowercase for case-insensitive matching.
			cfg.ja4_blocklist.insert(s.to_lowercase().into_boxed_str());
		}
	}

	cfg.tls_handshake_timeout_ms = prot.tls_handshake_timeout_ms.unwrap_or(0.0) as u64;
	cfg.require_sni = prot.require_sni.unwrap_or(false);

	let allowlist: Vec<IpNetwork> = prot
		.allowlist
		.as_deref()
		.unwrap_or(&[])
		.iter()
		.map(|s| {
			s.parse::<IpNetwork>()
				.map_err(|e| napi::Error::from_reason(format!("invalid allowlist CIDR '{s}': {e}")))
		})
		.collect::<Result<Vec<_>>>()?;

	let blocklist_strings: Vec<String> = prot
		.blocklist
		.as_deref()
		.unwrap_or(&[])
		.iter()
		.cloned()
		.collect();

	let blocklist: Vec<IpNetwork> = blocklist_strings
		.iter()
		.map(|s| {
			s.parse::<IpNetwork>()
				.map_err(|e| napi::Error::from_reason(format!("invalid blocklist CIDR '{s}': {e}")))
		})
		.collect::<Result<Vec<_>>>()?;

	Ok((cfg, allowlist, blocklist, blocklist_strings))
}

fn listener_tls_spec(l: &JsListenerConfig) -> ListenerTlsSpec {
	ListenerTlsSpec {
		cert_pem: l.default_cert.as_ref().map(|c| pem_bytes(&c.cert_chain)),
		key_pem: l.default_cert.as_ref().map(|c| pem_bytes(&c.private_key)),
		mtls_ca_pem: l.mtls.as_ref().map(|m| pem_bytes(&m.client_ca_cert)),
		require_client_cert: l.mtls.as_ref().and_then(|m| m.require_client_cert).unwrap_or(true),
	}
}

fn pem_bytes(v: &Either<String, Buffer>) -> Vec<u8> {
	match v {
		Either::A(s) => s.as_bytes().to_vec(),
		Either::B(b) => b.to_vec(),
	}
}

fn parse_source_address_mode(
	value: Option<&str>,
	has_uds_upstreams: bool,
) -> Result<SourceAddressMode> {
	match value {
		Some("proxyProtocol") => Ok(SourceAddressMode::ProxyProtocol),
		Some("xForwardedFor") => Ok(SourceAddressMode::XForwardedFor),
		Some("none") => Ok(SourceAddressMode::None),
		Some(other) => Err(napi::Error::from_reason(format!(
			"unknown sourceAddressHeader value '{other}'; expected 'proxyProtocol', 'xForwardedFor', or 'none'"
		))),
		// Default: proxyProtocol for UDS upstreams, none for TCP
		None => Ok(if has_uds_upstreams {
			SourceAddressMode::ProxyProtocol
		} else {
			SourceAddressMode::None
		}),
	}
}

fn num_cpus() -> u32 {
	std::thread::available_parallelism()
		.map(|n| n.get() as u32)
		.unwrap_or(4)
}

fn hex_to_bytes16(hex: &str) -> Option<[u8; 16]> {
	if hex.len() != 32 {
		return None;
	}
	let mut out = [0u8; 16];
	for (i, chunk) in hex.as_bytes().chunks(2).enumerate() {
		let hi = from_hex_digit(chunk[0])?;
		let lo = from_hex_digit(chunk[1])?;
		out[i] = (hi << 4) | lo;
	}
	Some(out)
}

fn from_hex_digit(b: u8) -> Option<u8> {
	match b {
		b'0'..=b'9' => Some(b - b'0'),
		b'a'..=b'f' => Some(b - b'a' + 10),
		b'A'..=b'F' => Some(b - b'A' + 10),
		_ => None,
	}
}
