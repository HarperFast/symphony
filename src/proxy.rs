use crate::listener::spawn_listeners;
use crate::metrics::{GlobalMetrics, ListenerMetrics};
use crate::protection::ProtectionState;
use crate::proxy_conn::{ConnContext, JsEvent};
use crate::router::{
	build_route_table, ListenerTlsSpec, LiveRouteTable, RouteSpec, UpstreamSpec,
};
use crate::suspended::{build_resolved_route, ResolveSpec, ResolveUpstream, SuspendedRegistry};
use ipnetwork::IpNetwork;
use napi::bindgen_prelude::*;
use napi::threadsafe_function::ThreadsafeFunction;
use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
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
	pub tls_handshake_timeout_ms: Option<f64>,
	pub require_sni: Option<bool>,
}

#[napi(object)]
pub struct JsListenerConfig {
	pub host: Option<String>,
	pub port: u16,
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
	pub upstreams: Vec<JsUpstream>,
	pub terminate_tls: bool,
	pub cert: Option<JsCertConfig>,
	pub mtls: Option<JsMtlsConfig>,
}

// ── Plain Rust internal config (all Send + Sync) ──────────────────────────────

/// Parsed listener config stored in the struct — no napi raw pointers.
struct InternalListener {
	addr: SocketAddr,
	max_connections: u32,
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
		let default_listener_tls = config
			.listeners
			.first()
			.map(listener_tls_spec)
			.unwrap_or_else(ListenerTlsSpec::empty);

		let worker_threads = config.worker_threads.unwrap_or(num_cpus()) as usize;
		let idle_timeout = Duration::from_millis(
			config
				.listeners
				.first()
				.and_then(|l| l.idle_timeout_ms)
				.unwrap_or(60_000.0) as u64,
		);
		let read_buffer_size = config.read_buffer_size.unwrap_or(65_536) as usize;

		let mut internal_listeners = Vec::new();
		let mut listener_states = Vec::new();

		for l in &config.listeners {
			let host = l.host.as_deref().unwrap_or("0.0.0.0");
			let addr_str = format!("{}:{}", host, l.port);
			let addr: SocketAddr = addr_str
				.parse()
				.map_err(|e| napi::Error::from_reason(format!("invalid listener address '{addr_str}': {e}")))?;

			internal_listeners.push(InternalListener {
				addr,
				max_connections: l.max_connections.unwrap_or(0),
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
		let table = build_route_table(&specs, &default_listener_tls)
			.map_err(|e| napi::Error::from_reason(e.to_string()))?;

		// Set up threadsafe event emitter
		let js_emit: ThreadsafeFunction<JsEvent> = emit_fn
			.create_threadsafe_function(128, |ctx| {
				let event: JsEvent = ctx.value;
				let env = ctx.env;
				let mut obj = env.create_object()?;
				match event {
					JsEvent::Blocked { ip, reason, listener } => {
						obj.set("type", "blocked")?;
						obj.set("ip", ip)?;
						obj.set("reason", reason)?;
						obj.set("listener", listener)?;
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
		})
	}

	#[napi]
	pub async fn start(&self) -> Result<()> {
		let (tx, _) = broadcast::channel(1);
		*self.shutdown_tx.lock().unwrap() = Some(tx.clone());

		for (i, listener) in self.listeners.iter().enumerate() {
			let state = &self.listener_states[i];
			let ctx = Arc::new(ConnContext {
				route_table: self.route_table.clone(),
				protection: state.protection.clone(),
				suspended_registry: self.suspended_registry.clone(),
				global_metrics: self.global_metrics.clone(),
				listener_metrics: state.metrics.clone(),
				listener_addr: state.addr.clone(),
				idle_timeout: self.idle_timeout,
				read_buffer_size: self.read_buffer_size,
				js_emit: self.js_emit.clone(),
			});

			let max_conn = listener.max_connections;
			let workers = self.worker_threads;
			let addr = listener.addr;
			let rx = tx.subscribe();

			tokio::spawn(async move {
				if let Err(e) = spawn_listeners(addr, workers, max_conn, ctx, rx).await {
					tracing::error!("listener {addr} failed: {e}");
				}
			});
		}

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
			let table = build_route_table(&specs, &self.default_listener_tls)
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

	Ok(RouteSpec {
		sni: r.sni.clone(),
		upstreams,
		terminate_tls: r.terminate_tls,
		cert_pem: r.cert.as_ref().map(|c| pem_bytes(&c.cert_chain)),
		key_pem: r.cert.as_ref().map(|c| pem_bytes(&c.private_key)),
		mtls_ca_pem: r.mtls.as_ref().map(|m| pem_bytes(&m.client_ca_cert)),
		require_client_cert: r.mtls.as_ref().and_then(|m| m.require_client_cert).unwrap_or(true),
		suspended: r.suspended.unwrap_or(false),
		suspend_timeout_ms: r.suspend_timeout_ms.unwrap_or(30_000.0) as u64,
	})
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
			Ok(UpstreamSpec::Tcp { host, port })
		}
		"uds" => {
			let path = u
				.path
				.clone()
				.ok_or_else(|| napi::Error::from_reason(format!("uds upstream for '{sni}' missing path")))?;
			Ok(UpstreamSpec::Uds {
				paths: vec![path],
				ip_affinity: u.ip_affinity.unwrap_or(false),
				affinity_ttl_ms: u.ip_affinity_ttl_ms.unwrap_or(300_000.0) as u64,
			})
		}
		other => Err(napi::Error::from_reason(format!(
			"unknown upstream kind '{other}' for sni '{sni}'"
		))),
	}
}

fn parse_resolve_spec(r: &JsResolveRoute) -> Result<ResolveSpec> {
	let upstream = r
		.upstreams
		.first()
		.ok_or_else(|| napi::Error::from_reason("resolveConnection: upstreams must not be empty".to_string()))
		.and_then(|u| match parse_upstream_spec(u, "<resolved>")? {
			UpstreamSpec::Tcp { host, port } => {
				let addr = format!("{host}:{port}")
					.parse()
					.map_err(|e| napi::Error::from_reason(format!("invalid address: {e}")))?;
				Ok(ResolveUpstream::Tcp(addr))
			}
			UpstreamSpec::Uds { paths, ip_affinity, affinity_ttl_ms } => {
				Ok(ResolveUpstream::Uds { paths, ip_affinity, affinity_ttl_ms })
			}
		})?;

	Ok(ResolveSpec {
		upstream,
		terminate_tls: r.terminate_tls,
		cert_pem: r.cert.as_ref().map(|c| pem_bytes(&c.cert_chain)),
		key_pem: r.cert.as_ref().map(|c| pem_bytes(&c.private_key)),
		mtls_ca_pem: r.mtls.as_ref().map(|m| pem_bytes(&m.client_ca_cert)),
		require_client_cert: r.mtls.as_ref().and_then(|m| m.require_client_cert).unwrap_or(true),
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

	cfg.tls_handshake_timeout_ms = prot.tls_handshake_timeout_ms.unwrap_or(0.0) as u64;
	cfg.require_sni = prot.require_sni.unwrap_or(false);

	let allowlist: Vec<IpNetwork> = prot
		.allowlist
		.as_deref()
		.unwrap_or(&[])
		.iter()
		.filter_map(|s| s.parse().ok())
		.collect();

	let blocklist_strings: Vec<String> = prot
		.blocklist
		.as_deref()
		.unwrap_or(&[])
		.iter()
		.cloned()
		.collect();

	let blocklist: Vec<IpNetwork> = blocklist_strings.iter().filter_map(|s| s.parse().ok()).collect();

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
