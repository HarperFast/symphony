use crate::http_listener::spawn_http_listeners;
use crate::listener::spawn_listeners;
use crate::metrics::{total_of, GlobalMetrics, ListenerMetrics};
use crate::protection::ProtectionState;
use crate::proxy_conn::{
	ConnContext, JsEvent, DEFAULT_COPY_BUFFER_SIZE, MAX_COPY_BUFFER_SIZE, MIN_COPY_BUFFER_SIZE,
};
use crate::router::{
	build_route_table, requires_http_protocol, ForwardFingerprint, ListenerTlsSpec, LiveRouteTable,
	RouteProtocol, RouteSpec, SourceAddressMode, UpstreamSpec,
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
	/// "proxyProtocol" (v1, default for UDS), "proxyProtocolV2", "xForwardedFor", or
	/// "none" (default for TCP).
	pub source_address_header: Option<String>,
	/// Which client TLS fingerprint to forward downstream: "ja3", "ja4", or "none"
	/// (default). Carried as a PROXY v2 TLV under "proxyProtocolV2", otherwise as an
	/// injected X-JA3/X-JA4 HTTP header.
	pub forward_fingerprint: Option<String>,
	/// Advertise h2 in ALPN so clients can negotiate HTTP/2. Default: false.
	pub http2: Option<bool>,
	/// The route's application protocol: `'http'` or `'opaque'` (non-HTTP, e.g. MQTT).
	/// Required — as a parse-time error, not a silent no-op — whenever the route requests a
	/// header-injection forwarding mode (`sourceAddressHeader: 'xForwardedFor'`, or
	/// `forwardFingerprint` under any mode other than `'proxyProtocolV2'`): ALPN alone can't
	/// tell a native non-HTTP protocol (which negotiates no ALPN) from an HTTPS client that
	/// simply offered none, so the declaration must be explicit. Default: `'opaque'`.
	pub protocol: Option<String>,
}

#[napi(object)]
pub struct JsRateLimitConfig {
	pub connections_per_second: f64,
	pub burst: Option<f64>,
}

#[napi(object)]
pub struct JsSustainedRateLimitConfig {
	pub connections_per_minute: f64,
	pub burst: Option<f64>,
}

#[napi(object)]
pub struct JsPenaltyBoxConfig {
	/// Duration in ms an IP remains blocked after exhausting a rate limit. Default: 600000.
	pub duration_ms: Option<f64>,
}

#[napi(object)]
pub struct JsProtectionConfig {
	pub rate_limit: Option<JsRateLimitConfig>,
	/// Sustained (per-minute) token bucket — independent of the per-second bucket.
	pub sustained: Option<JsSustainedRateLimitConfig>,
	/// Penalty box: block an IP for a configurable duration after any rate limit exhaustion.
	pub penalty_box: Option<JsPenaltyBoxConfig>,
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
	/// Per-direction copy buffer, in bytes (default 8192). One buffer per direction is held for
	/// the whole life of every proxied connection, idle or not, so these are a direct multiplier
	/// on per-connection memory: `(client + upstream) × connections`, i.e.
	/// `2 × readBufferSize × connections` when both directions use this value.
	pub read_buffer_size: Option<u32>,
	/// Overrides `readBufferSize` for the client→upstream direction only.
	pub client_read_buffer_size: Option<u32>,
	/// Overrides `readBufferSize` for the upstream→client direction only.
	pub upstream_read_buffer_size: Option<u32>,
}

#[napi(object)]
pub struct JsListenerProtectionHotConfig {
	/// Port of the listener to update. Must match a listener configured at start.
	pub port: u16,
	pub protection: JsProtectionConfig,
}

#[napi(object)]
pub struct JsHotConfig {
	pub routes: Option<Vec<JsRouteConfig>>,
	/// Per-listener protection updates. Each entry must reference a listener that was
	/// started WITH protection; a mismatched port or a port without protection is an error.
	pub protection: Option<Vec<JsListenerProtectionHotConfig>>,
}

/// A single labelled counter — one entry per block/error reason.
#[napi(object)]
pub struct JsLabeledCount {
	pub reason: String,
	pub count: f64,
}

#[napi(object)]
pub struct JsListenerMetrics {
	/// "host:port" — matches the `listener` field on emitted events.
	pub address: String,
	/// "tls" or "http".
	pub mode: String,
	pub active_connections: f64,
	pub accepted: f64,
	pub blocked: f64,
	pub errors: f64,
	/// Bytes read from clients (client → upstream).
	pub bytes_received: f64,
	/// Bytes written to clients (upstream → client).
	pub bytes_sent: f64,
	pub blocked_by_reason: Vec<JsLabeledCount>,
	pub errors_by_reason: Vec<JsLabeledCount>,
}

// Counters are reported as f64 because napi maps u64 to BigInt, which JSON.stringify cannot
// serialise. f64 is exact to 2^53, so a byte counter stays exact past 9 PB per listener.
#[napi(object)]
pub struct JsProxyMetrics {
	pub active_connections: f64,
	pub blocked_connections: f64,
	pub pending_suspended: f64,
	/// Suspended connections that JS resolved with a route.
	pub suspended_resolved: f64,
	/// Suspended connections that timed out or were rejected.
	pub suspended_unresolved: f64,
	/// Routes currently in the live table, including the default route.
	pub routes: f64,
	/// Routes whose cert failed to build — dropped, or serving a carried-forward last-good cert.
	pub failing_routes: f64,
	pub listeners: Vec<JsListenerMetrics>,
}

#[napi(object)]
pub struct JsBlockedIpsInfo {
	pub rate_limited: Vec<String>,
	pub concurrency_limited: Vec<String>,
	pub cidr_blocklist: Vec<String>,
	/// IPs currently in the penalty box (blocked for a configured duration after rate-limit exhaustion).
	pub penalty_boxed: Vec<String>,
}

#[napi(object)]
pub struct JsResolveRoute {
	pub upstream: JsUpstream,
	pub terminate_tls: bool,
	pub cert: Option<JsCertConfig>,
	pub mtls: Option<JsMtlsConfig>,
	pub source_address_header: Option<String>,
	pub forward_fingerprint: Option<String>,
	pub http2: Option<bool>,
	/// See `JsRouteConfig::protocol` — the same declaration, required under the same
	/// conditions, for a route resolved via `resolveConnection()`.
	pub protocol: Option<String>,
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

fn labeled_counts(counts: Vec<(&'static str, u64)>) -> Vec<JsLabeledCount> {
	counts
		.into_iter()
		.map(|(reason, count)| JsLabeledCount { reason: reason.to_string(), count: count as f64 })
		.collect()
}

/// Per-listener runtime state.
struct ListenerState {
	addr: String,
	port: u16,
	metrics: Arc<ListenerMetrics>,
	protection: Option<Arc<ProtectionState>>,
}

// ── SymphonyProxy napi class ──────────────────────────────────────────────────

#[napi]
pub struct SymphonyProxyWrap {
	// Plain-Rust config (all Send + Sync)
	listeners: Vec<InternalListener>,
	default_listener_tls: ListenerTlsSpec,
	worker_threads: usize,
	idle_timeout: Duration,
	client_read_buffer_size: usize,
	upstream_read_buffer_size: usize,
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
		let base_read_buffer_size = resolve_copy_buffer_size(config.read_buffer_size, "readBufferSize");
		let client_read_buffer_size = match config.client_read_buffer_size {
			Some(v) => resolve_copy_buffer_size(Some(v), "clientReadBufferSize"),
			None => base_read_buffer_size,
		};
		let upstream_read_buffer_size = match config.upstream_read_buffer_size {
			Some(v) => resolve_copy_buffer_size(Some(v), "upstreamReadBufferSize"),
			None => base_read_buffer_size,
		};

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

			let protection = if let Some(prot_cfg) = &l.protection {
				let cfg = parse_protection_config(prot_cfg)?;
				Some(ProtectionState::new(cfg))
			} else {
				None
			};

			listener_states.push(ListenerState {
				addr: addr_str,
				port: l.port,
				metrics: Arc::new(ListenerMetrics::default()),
				protection,
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
			client_read_buffer_size,
			upstream_read_buffer_size,
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
				client_read_buffer_size: self.client_read_buffer_size,
				upstream_read_buffer_size: self.upstream_read_buffer_size,
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

		// Spawn a periodic IP state eviction task per listener that has protection.
		// Eviction bounds ip_table memory growth under diverse-IP traffic / attack.
		// evict() is O(N) DashMap::retain with shard locks and per-entry float math —
		// running it directly inside select! would stall the accept path under diverse-IP
		// flood. spawn_blocking moves it off the tokio worker thread pool.
		for ls in &self.listener_states {
			if let Some(prot) = ls.protection.clone() {
				let mut evict_rx = tx.subscribe();
				self.rt_handle.spawn(async move {
					let interval = Duration::from_secs(60);
					loop {
						tokio::select! {
							_ = evict_rx.recv() => break,
							_ = tokio::time::sleep(interval) => {
								let prot_clone = prot.clone();
								// Fire-and-forget: an in-flight eviction completing during
								// shutdown is harmless (it just holds a DashMap shard lock briefly).
								let _ = tokio::task::spawn_blocking(move || prot_clone.evict()).await;
							}
						}
					}
				});
			}
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
		// Build new route table if provided — hold it, do NOT swap yet.
		// All validation must pass before either section is applied: a combined update
		// with valid routes + invalid protection must leave both in their old state.
		let new_route_table = if let Some(routes) = hot.routes {
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
			Some(table)
		} else {
			None
		};

		// Validate + parse protection updates if provided — all-or-nothing before any store.
		let validated_protection = if let Some(protection_updates) = hot.protection {
			// Phase 1: validate all updates (atomicity + early error).
			// Collect all offending ports so the caller gets one actionable error.
			let mut errors: Vec<String> = Vec::new();
			for update in &protection_updates {
				let matches: Vec<_> =
					self.listener_states.iter().filter(|s| s.port == update.port).collect();
				match matches.as_slice() {
					[] => errors.push(format!("port {} matches no listener", update.port)),
					[single] if single.protection.is_none() => errors.push(format!(
						"port {} was started without protection; recreate to enable",
						update.port
					)),
					[_single] => {} // valid — exactly one protection-enabled listener
					_multiple => errors.push(format!(
						"port {} matches multiple listeners; use per-listener restart-configure",
						update.port
					)),
				}
			}
			if !errors.is_empty() {
				return Err(napi::Error::from_reason(errors.join("; ")));
			}

			// Phase 2: parse all configs (fallible).
			let parsed = protection_updates
				.iter()
				.map(|u| parse_protection_config(&u.protection))
				.collect::<Result<Vec<_>>>()?;

			Some((protection_updates, parsed))
		} else {
			None
		};

		// All validation passed — apply atomically (routes then protection, neither applied on any error above).
		if let Some(table) = new_route_table {
			self.route_table.swap(table);
		}
		if let Some((protection_updates, parsed)) = validated_protection {
			// Phase 3: store all (infallible — validation above guarantees each port is valid).
			for (update, cfg) in protection_updates.iter().zip(parsed) {
				let prot = self
					.listener_states
					.iter()
					.find(|s| s.port == update.port)
					.and_then(|s| s.protection.as_ref())
					.expect("validated above");
				prot.config.store(Arc::new(cfg));
			}
		}
		Ok(())
	}

	#[napi]
	pub fn metrics(&self) -> JsProxyMetrics {
		let table = self.route_table.0.load();

		// `listeners` and `listener_states` are built in lockstep in the constructor and never
		// mutated, so index i refers to the same listener in both.
		//
		// Each listener's totals are summed from the very reason values it reports, so a scrape
		// taken mid-traffic is internally consistent — a separately maintained total would be a
		// second write racing the first and could disagree with its own breakdown.
		let listeners: Vec<JsListenerMetrics> = self
			.listeners
			.iter()
			.zip(self.listener_states.iter())
			.map(|(listener, state)| {
				let blocked_by_reason = state.metrics.blocked_by_reason();
				let errors_by_reason = state.metrics.errors_by_reason();
				JsListenerMetrics {
					address: state.addr.clone(),
					mode: match listener.mode {
						ListenerMode::Tls => "tls".to_string(),
						ListenerMode::Http => "http".to_string(),
					},
					active_connections: state.metrics.active_connections.load(Ordering::Relaxed) as f64,
					accepted: state.metrics.total_accepted.load(Ordering::Relaxed) as f64,
					blocked: total_of(&blocked_by_reason) as f64,
					errors: total_of(&errors_by_reason) as f64,
					bytes_received: state.metrics.bytes_in.load(Ordering::Relaxed) as f64,
					bytes_sent: state.metrics.bytes_out.load(Ordering::Relaxed) as f64,
					blocked_by_reason: labeled_counts(blocked_by_reason),
					errors_by_reason: labeled_counts(errors_by_reason),
				}
			})
			.collect();

		// Likewise derived, so the proxy-wide total always equals the sum of the listener values
		// in this same snapshot.
		let blocked_connections = listeners.iter().map(|l| l.blocked).sum();

		JsProxyMetrics {
			active_connections: self.global_metrics.active_connections.load(Ordering::Relaxed) as f64,
			blocked_connections,
			pending_suspended: self.global_metrics.pending_suspended.load(Ordering::Relaxed) as f64,
			suspended_resolved: self.global_metrics.suspended_resolved.load(Ordering::Relaxed) as f64,
			suspended_unresolved: self.global_metrics.suspended_unresolved.load(Ordering::Relaxed) as f64,
			routes: table.route_count() as f64,
			failing_routes: table.failing_route_count() as f64,
			listeners,
		}
	}

	#[napi]
	pub fn blocked_ips(&self) -> JsBlockedIpsInfo {
		use std::collections::HashSet as HSet;
		let mut rate_limited_set: HSet<String> = HSet::new();
		let mut concurrency_limited_set: HSet<String> = HSet::new();
		let mut cidr_blocklist_set: HSet<String> = HSet::new();
		let mut penalty_boxed_set: HSet<String> = HSet::new();

		for state in &self.listener_states {
			if let Some(prot) = &state.protection {
				let cfg = prot.config.load();
				// Blocklist is live-readable from the hot-swappable config snapshot.
				for net in &cfg.blocklist {
					cidr_blocklist_set.insert(net.to_string());
				}
				let (rl, cl, pb) = prot.blocked_ips();
				for ip in rl {
					rate_limited_set.insert(ip.to_string());
				}
				for ip in cl {
					concurrency_limited_set.insert(ip.to_string());
				}
				for ip in pb {
					penalty_boxed_set.insert(ip.to_string());
				}
			}
		}

		JsBlockedIpsInfo {
			rate_limited: rate_limited_set.into_iter().collect(),
			concurrency_limited: concurrency_limited_set.into_iter().collect(),
			cidr_blocklist: cidr_blocklist_set.into_iter().collect(),
			penalty_boxed: penalty_boxed_set.into_iter().collect(),
		}
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
	let forward_fingerprint = parse_forward_fingerprint(r.forward_fingerprint.as_deref())?;
	let protocol = parse_route_protocol(r.protocol.as_deref())?;

	if requires_http_protocol(source_address_mode, forward_fingerprint) && protocol != RouteProtocol::Http {
		return Err(napi::Error::from_reason(format!(
			"route '{}': sourceAddressHeader 'xForwardedFor', or forwardFingerprint via an HTTP header (any mode other than 'proxyProtocolV2'), requires protocol: 'http' — declare it explicitly, or switch to 'proxyProtocol'/'proxyProtocolV2' which work on any protocol",
			r.sni
		)));
	}

	let spec = RouteSpec {
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
		forward_fingerprint,
		http2: r.http2.unwrap_or(false),
		protocol,
	};

	if spec.http2 && !spec.terminate_tls {
		eprintln!("symphony: route '{}': http2=true has no effect when terminateTls=false (passthrough mode)", spec.sni);
	}
	// An injected X-JA3/X-JA4 header needs a plaintext HTTP/1 upstream (terminated, not h2); the
	// runtime skips it otherwise. The PROXY v2 TLV carrier works everywhere (it prefixes the raw
	// bytes), so steer non-HTTP/1 routes to it.
	if forward_fingerprint != ForwardFingerprint::None
		&& source_address_mode != SourceAddressMode::ProxyProtocolV2
		&& (!spec.terminate_tls || spec.http2)
	{
		eprintln!(
			"symphony: route '{}': forwardFingerprint via HTTP header has no effect on a non-HTTP/1 upstream (terminateTls=false or http2=true); use sourceAddressHeader='proxyProtocolV2'",
			spec.sni
		);
	}
	Ok(spec)
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
	let forward_fingerprint = parse_forward_fingerprint(r.forward_fingerprint.as_deref())?;
	let protocol = parse_route_protocol(r.protocol.as_deref())?;

	if requires_http_protocol(source_address_mode, forward_fingerprint) && protocol != RouteProtocol::Http {
		return Err(napi::Error::from_reason(
			"resolveConnection: sourceAddressHeader 'xForwardedFor', or forwardFingerprint via an HTTP header (any mode other than 'proxyProtocolV2'), requires protocol: 'http' — declare it explicitly, or switch to 'proxyProtocol'/'proxyProtocolV2' which work on any protocol".to_string(),
		));
	}

	Ok(ResolveSpec {
		upstream,
		terminate_tls: r.terminate_tls,
		cert_pem: r.cert.as_ref().map(|c| pem_bytes(&c.cert_chain)),
		key_pem: r.cert.as_ref().map(|c| pem_bytes(&c.private_key)),
		mtls_ca_pem: r.mtls.as_ref().map(|m| pem_bytes(&m.client_ca_cert)),
		require_client_cert: r.mtls.as_ref().and_then(|m| m.require_client_cert).unwrap_or(false),
		source_address_mode,
		forward_fingerprint,
		http2: r.http2.unwrap_or(false),
		protocol,
	})
}

fn parse_protection_config(
	prot: &JsProtectionConfig,
) -> Result<crate::protection::ProtectionConfig> {
	let mut cfg = crate::protection::ProtectionConfig::default();

	if let Some(rl) = &prot.rate_limit {
		if !rl.connections_per_second.is_finite() || rl.connections_per_second <= 0.0 {
			return Err(napi::Error::from_reason(format!(
				"rateLimit.connectionsPerSecond must be a finite positive number, got {}",
				rl.connections_per_second
			)));
		}
		if let Some(burst) = rl.burst {
			if !burst.is_finite() || burst < 0.0 {
				return Err(napi::Error::from_reason(format!(
					"rateLimit.burst must be a finite non-negative number, got {burst}"
				)));
			}
		}
		cfg.rate_limit_cps = Some(rl.connections_per_second);
		cfg.rate_limit_burst = rl.burst;
	}
	if let Some(s) = &prot.sustained {
		if !s.connections_per_minute.is_finite() || s.connections_per_minute <= 0.0 {
			return Err(napi::Error::from_reason(format!(
				"sustained.connectionsPerMinute must be a finite positive number, got {}",
				s.connections_per_minute
			)));
		}
		if let Some(burst) = s.burst {
			if !burst.is_finite() || burst < 0.0 {
				return Err(napi::Error::from_reason(format!(
					"sustained.burst must be a finite non-negative number, got {burst}"
				)));
			}
		}
		cfg.sustained_cpm = Some(s.connections_per_minute);
		cfg.sustained_burst = s.burst;
	}
	if let Some(pb) = &prot.penalty_box {
		cfg.penalty_box_duration_ms = pb.duration_ms.unwrap_or(600_000.0) as u64;
	}
	cfg.max_concurrent_per_ip = prot.max_concurrent_per_ip.unwrap_or(0);

	if let Some(ja3s) = &prot.ja3_blocklist {
		for hex in ja3s {
			// A JA3 is an MD5 digest — exactly 32 hex chars. Reject typos rather than
			// silently installing an entry that can never match.
			let bytes = hex_to_bytes16(hex).ok_or_else(|| {
				napi::Error::from_reason(format!(
					"invalid ja3Blocklist entry '{hex}': expected 32 hex characters"
				))
			})?;
			cfg.ja3_blocklist.insert(bytes);
		}
	}

	if let Some(ja4s) = &prot.ja4_blocklist {
		for s in ja4s {
			// Normalize to lowercase *before* validating — matching is case-insensitive, so an
			// otherwise-well-formed uppercase fingerprint must not be rejected here.
			let lower = s.to_lowercase();
			// Validate against what `compute_ja4` can actually produce, so a malformed or
			// unreachable entry fails at config time instead of silently never matching.
			if !is_valid_ja4(&lower) {
				return Err(napi::Error::from_reason(format!(
					"invalid ja4Blocklist entry '{s}': expected JA4 format t<ver><sni><cc><ec><alpn>_<12 hex>_<12 hex> (36 chars)"
				)));
			}
			cfg.ja4_blocklist.insert(lower.into_boxed_str());
		}
	}

	cfg.tls_handshake_timeout_ms = prot.tls_handshake_timeout_ms.unwrap_or(0.0) as u64;
	cfg.require_sni = prot.require_sni.unwrap_or(false);

	cfg.allowlist = prot
		.allowlist
		.as_deref()
		.unwrap_or(&[])
		.iter()
		.map(|s| {
			s.parse::<IpNetwork>()
				.map_err(|e| napi::Error::from_reason(format!("invalid allowlist CIDR '{s}': {e}")))
		})
		.collect::<Result<Vec<_>>>()?;

	cfg.blocklist = prot
		.blocklist
		.as_deref()
		.unwrap_or(&[])
		.iter()
		.map(|s| {
			s.parse::<IpNetwork>()
				.map_err(|e| napi::Error::from_reason(format!("invalid blocklist CIDR '{s}': {e}")))
		})
		.collect::<Result<Vec<_>>>()?;

	Ok(cfg.precompute())
}

fn listener_tls_spec(l: &JsListenerConfig) -> ListenerTlsSpec {
	ListenerTlsSpec {
		cert_pem: l.default_cert.as_ref().map(|c| pem_bytes(&c.cert_chain)),
		key_pem: l.default_cert.as_ref().map(|c| pem_bytes(&c.private_key)),
		mtls_ca_pem: l.mtls.as_ref().map(|m| pem_bytes(&m.client_ca_cert)),
		require_client_cert: l.mtls.as_ref().and_then(|m| m.require_client_cert).unwrap_or(true),
	}
}

/// Resolve one direction's copy buffer size, clamping rather than rejecting: a buffer of 0 would
/// make the copy loop read into an empty slice and mistake the `Ok(0)` for EOF, so the floor is a
/// correctness guard, not a preference. Out-of-range values are logged so a silently-ignored
/// config value can't masquerade as an applied one — `label` is the key the operator actually set,
/// not the direction being resolved, or the warning names a field they never wrote.
fn resolve_copy_buffer_size(configured: Option<u32>, label: &str) -> usize {
	let requested = configured.map_or(DEFAULT_COPY_BUFFER_SIZE, |v| v as usize);
	let clamped = requested.clamp(MIN_COPY_BUFFER_SIZE, MAX_COPY_BUFFER_SIZE);
	if clamped != requested {
		tracing::warn!(
			"{label} {requested} is outside [{MIN_COPY_BUFFER_SIZE}, {MAX_COPY_BUFFER_SIZE}]; using {clamped}"
		);
	}
	clamped
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
		Some("proxyProtocolV2") => Ok(SourceAddressMode::ProxyProtocolV2),
		Some("xForwardedFor") => Ok(SourceAddressMode::XForwardedFor),
		Some("none") => Ok(SourceAddressMode::None),
		Some(other) => Err(napi::Error::from_reason(format!(
			"unknown sourceAddressHeader value '{other}'; expected 'proxyProtocol', 'proxyProtocolV2', 'xForwardedFor', or 'none'"
		))),
		// Default: proxyProtocol for UDS upstreams, none for TCP
		None => Ok(if has_uds_upstreams {
			SourceAddressMode::ProxyProtocol
		} else {
			SourceAddressMode::None
		}),
	}
}

fn parse_forward_fingerprint(value: Option<&str>) -> Result<ForwardFingerprint> {
	match value {
		None | Some("none") => Ok(ForwardFingerprint::None),
		Some("ja3") => Ok(ForwardFingerprint::Ja3),
		Some("ja4") => Ok(ForwardFingerprint::Ja4),
		Some(other) => Err(napi::Error::from_reason(format!(
			"unknown forwardFingerprint value '{other}'; expected 'ja3', 'ja4', or 'none'"
		))),
	}
}

fn parse_route_protocol(value: Option<&str>) -> Result<RouteProtocol> {
	match value {
		None | Some("opaque") => Ok(RouteProtocol::Opaque),
		Some("http") => Ok(RouteProtocol::Http),
		Some(other) => Err(napi::Error::from_reason(format!(
			"unknown protocol value '{other}'; expected 'http' or 'opaque'"
		))),
	}
}

fn num_cpus() -> u32 {
	std::thread::available_parallelism()
		.map(|n| n.get() as u32)
		.unwrap_or(4)
}

/// Validate a JA4 core-TLS fingerprint string: `t<ver2><sni1><cc2><ec2><alpn2>_<12hex>_<12hex>`
/// (36 chars). Expects lowercase input (call sites normalize before validating). Restricted to
/// exactly what `sni::compute_ja4` can produce — not the full JA4 spec — since a blocklist entry
/// symphony itself can never emit (a `q`/`d` transport prefix, or a TLS version it doesn't speak)
/// would pass validation yet can never match, defeating the point of validating it at all.
fn is_valid_ja4(s: &str) -> bool {
	let b = s.as_bytes();
	if b.len() != 36 || b[10] != b'_' || b[23] != b'_' {
		return false;
	}
	let a = &b[..10];
	// protocol: symphony only speaks TLS-over-TCP, so only 't' (never 'q'=QUIC, 'd'=DTLS).
	// tls version: only the 2-digit strings compute_ja4's ver_str match can emit.
	// sni presence (d=domain/i=ip), cipher count (2 digits), extension count (2 digits),
	// alpn first/last (2 alphanumeric).
	a[0] == b't'
		&& matches!((a[1], a[2]), (b'0', b'0') | (b'1', b'0') | (b'1', b'1') | (b'1', b'2') | (b'1', b'3'))
		&& matches!(a[3], b'd' | b'i')
		&& a[4].is_ascii_digit()
		&& a[5].is_ascii_digit()
		&& a[6].is_ascii_digit()
		&& a[7].is_ascii_digit()
		&& a[8].is_ascii_alphanumeric()
		&& a[9].is_ascii_alphanumeric()
		&& b[11..23].iter().all(u8::is_ascii_hexdigit)
		&& b[24..36].iter().all(u8::is_ascii_hexdigit)
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

#[cfg(test)]
mod tests {
	use super::*;

	fn no_rate_limit_prot() -> JsProtectionConfig {
		JsProtectionConfig {
			rate_limit: None,
			sustained: None,
			penalty_box: None,
			max_concurrent_per_ip: None,
			allowlist: None,
			blocklist: None,
			ja3_blocklist: None,
			ja4_blocklist: None,
			tls_handshake_timeout_ms: None,
			require_sni: None,
		}
	}

	#[test]
	fn reject_nan_cps() {
		let prot = JsProtectionConfig {
			rate_limit: Some(JsRateLimitConfig { connections_per_second: f64::NAN, burst: None }),
			..no_rate_limit_prot()
		};
		assert!(parse_protection_config(&prot).is_err(), "NaN cps must error");
	}

	#[test]
	fn reject_negative_cps() {
		let prot = JsProtectionConfig {
			rate_limit: Some(JsRateLimitConfig { connections_per_second: -1.0, burst: None }),
			..no_rate_limit_prot()
		};
		assert!(parse_protection_config(&prot).is_err(), "negative cps must error");
	}

	#[test]
	fn reject_zero_cps() {
		let prot = JsProtectionConfig {
			rate_limit: Some(JsRateLimitConfig { connections_per_second: 0.0, burst: None }),
			..no_rate_limit_prot()
		};
		assert!(parse_protection_config(&prot).is_err(), "zero cps must error");
	}

	#[test]
	fn copy_buffer_default_matches_the_copy_loop() {
		// The default has to equal what the copy loop used while `readBufferSize` was inert,
		// or wiring it through would have silently changed every deployment's footprint.
		assert_eq!(resolve_copy_buffer_size(None, "test"), DEFAULT_COPY_BUFFER_SIZE);
	}

	#[test]
	fn copy_buffer_size_is_clamped_not_rejected() {
		// Zero would make the copy loop read into an empty slice and read the Ok(0) as EOF.
		assert_eq!(resolve_copy_buffer_size(Some(0), "test"), MIN_COPY_BUFFER_SIZE);
		assert_eq!(resolve_copy_buffer_size(Some(u32::MAX), "test"), MAX_COPY_BUFFER_SIZE);
		assert_eq!(resolve_copy_buffer_size(Some(1024), "test"), 1024);
	}

	#[test]
	fn reject_nan_burst() {
		let prot = JsProtectionConfig {
			rate_limit: Some(JsRateLimitConfig {
				connections_per_second: 10.0,
				burst: Some(f64::NAN),
			}),
			..no_rate_limit_prot()
		};
		assert!(parse_protection_config(&prot).is_err(), "NaN burst must error");
	}

	#[test]
	fn reject_negative_burst() {
		let prot = JsProtectionConfig {
			rate_limit: Some(JsRateLimitConfig {
				connections_per_second: 10.0,
				burst: Some(-1.0),
			}),
			..no_rate_limit_prot()
		};
		assert!(parse_protection_config(&prot).is_err(), "negative burst must error");
	}

	#[test]
	fn reject_nan_cpm() {
		let prot = JsProtectionConfig {
			sustained: Some(JsSustainedRateLimitConfig {
				connections_per_minute: f64::NAN,
				burst: None,
			}),
			..no_rate_limit_prot()
		};
		assert!(parse_protection_config(&prot).is_err(), "NaN cpm must error");
	}

	#[test]
	fn reject_negative_cpm() {
		let prot = JsProtectionConfig {
			sustained: Some(JsSustainedRateLimitConfig {
				connections_per_minute: -1.0,
				burst: None,
			}),
			..no_rate_limit_prot()
		};
		assert!(parse_protection_config(&prot).is_err(), "negative cpm must error");
	}

	#[test]
	fn accept_absent_burst() {
		// burst: None (absent) must not error — only present-but-invalid burst is rejected
		let prot = JsProtectionConfig {
			rate_limit: Some(JsRateLimitConfig { connections_per_second: 10.0, burst: None }),
			sustained: Some(JsSustainedRateLimitConfig {
				connections_per_minute: 100.0,
				burst: None,
			}),
			..no_rate_limit_prot()
		};
		assert!(parse_protection_config(&prot).is_ok(), "absent burst must be accepted");
	}

	#[test]
	fn valid_ja4_accepts_well_formed() {
		assert!(is_valid_ja4("t13d1516h2_8daaf6152771_02713d6af862"));
		assert!(is_valid_ja4("t00i070500_1234567890ab_abcdef012345")); // version 00, no-SNI variant
		for ver in ["00", "10", "11", "12", "13"] {
			let s = format!("t{ver}d1516h2_8daaf6152771_02713d6af862");
			assert!(is_valid_ja4(&s), "version {ver} should be accepted: {s}");
		}
	}

	#[test]
	fn valid_ja4_rejects_malformed() {
		assert!(!is_valid_ja4(""), "empty");
		assert!(!is_valid_ja4("t13d1516h2_8daaf6152771"), "missing part C");
		assert!(!is_valid_ja4("t13d1516h2_8daaf6152771_02713d6af86"), "part C too short");
		assert!(!is_valid_ja4("t13d1516h2_8daaf6152771_02713d6af862x"), "too long");
		assert!(!is_valid_ja4("t13d1516h2-8daaf6152771-02713d6af862"), "wrong separators");
		assert!(!is_valid_ja4("t13d1516h2_8daaf615277g_02713d6af862"), "non-hex in part B");
		assert!(!is_valid_ja4("x13d1516h2_8daaf6152771_02713d6af862"), "bad protocol char");
		assert!(!is_valid_ja4("t1xd1516h2_8daaf6152771_02713d6af862"), "non-digit version");
		// Uppercase must be rejected here — call sites are expected to normalize before
		// validating; is_valid_ja4 itself only matches the lowercase output compute_ja4 emits.
		assert!(!is_valid_ja4("T13D1516H2_8DAAF6152771_02713D6AF862"), "uppercase");
	}

	fn base_route_config(sni: &str) -> JsRouteConfig {
		JsRouteConfig {
			sni: sni.to_string(),
			upstreams: vec![JsUpstream {
				kind: "tcp".to_string(),
				host: Some("127.0.0.1".to_string()),
				port: Some(8080),
				path: None,
				ip_affinity: None,
				ip_affinity_ttl_ms: None,
				pid: None,
				tid: None,
				protocol: None,
			}],
			terminate_tls: false,
			cert: None,
			mtls: None,
			suspended: None,
			suspend_timeout_ms: None,
			max_connections_per_second: None,
			burst: None,
			source_address_header: None,
			forward_fingerprint: None,
			http2: None,
			protocol: None,
		}
	}

	#[test]
	fn xff_without_protocol_declaration_is_rejected() {
		let mut r = base_route_config("mqtt.example.com");
		r.source_address_header = Some("xForwardedFor".to_string());
		let err = parse_route_spec(&r).expect_err("xForwardedFor without protocol: 'http' must error");
		assert!(
			err.to_string().contains("protocol"),
			"error message must mention the missing declaration: {err}"
		);
	}

	#[test]
	fn xff_with_http_protocol_declared_is_accepted() {
		let mut r = base_route_config("app.example.com");
		r.source_address_header = Some("xForwardedFor".to_string());
		r.protocol = Some("http".to_string());
		assert!(parse_route_spec(&r).is_ok(), "xForwardedFor with protocol: 'http' must be accepted");
	}

	#[test]
	fn opaque_route_with_proxy_protocol_is_accepted() {
		let mut r = base_route_config("mqtt.example.com");
		r.source_address_header = Some("proxyProtocol".to_string());
		// protocol left unset (defaults to 'opaque') — PROXY protocol works on any byte stream.
		assert!(parse_route_spec(&r).is_ok(), "opaque route with proxyProtocol must be accepted");
	}

	#[test]
	fn opaque_route_requesting_xff_is_rejected() {
		let mut r = base_route_config("mqtt.example.com");
		r.source_address_header = Some("xForwardedFor".to_string());
		r.protocol = Some("opaque".to_string());
		assert!(
			parse_route_spec(&r).is_err(),
			"an explicitly opaque route requesting xForwardedFor must still be rejected"
		);
	}

	#[test]
	fn header_carried_fingerprint_without_protocol_declaration_is_rejected() {
		let mut r = base_route_config("app.example.com");
		r.forward_fingerprint = Some("ja3".to_string());
		// source_address_header left at 'none' — not proxyProtocolV2, so the fingerprint
		// would ride an X-JA3 header and needs the declaration too.
		assert!(
			parse_route_spec(&r).is_err(),
			"header-carried forwardFingerprint without protocol: 'http' must error"
		);
	}

	#[test]
	fn fingerprint_under_proxy_protocol_v2_needs_no_declaration() {
		let mut r = base_route_config("mqtt.example.com");
		r.source_address_header = Some("proxyProtocolV2".to_string());
		r.forward_fingerprint = Some("ja4".to_string());
		// TLV carrier, not a header — no protocol declaration required.
		assert!(parse_route_spec(&r).is_ok(), "forwardFingerprint under proxyProtocolV2 must not require protocol");
	}

	#[test]
	fn unknown_protocol_value_is_rejected() {
		let mut r = base_route_config("app.example.com");
		r.protocol = Some("mqtt".to_string());
		assert!(parse_route_spec(&r).is_err(), "an unrecognized protocol value must error");
	}

	#[test]
	fn valid_ja4_rejects_transports_and_versions_symphony_cannot_emit() {
		// symphony only speaks TLS-over-TCP: 'q' (QUIC) and 'd' (DTLS) transport prefixes can
		// never match a fingerprint symphony itself computes.
		assert!(!is_valid_ja4("q13i070500_1234567890ab_abcdef012345"), "QUIC prefix");
		assert!(!is_valid_ja4("d13i070500_1234567890ab_abcdef012345"), "DTLS prefix");
		// compute_ja4's ver_str only ever emits 00/10/11/12/13 — any other 2-digit value can
		// never match either.
		for ver in ["01", "02", "14", "20", "99"] {
			let s = format!("t{ver}d1516h2_8daaf6152771_02713d6af862");
			assert!(!is_valid_ja4(&s), "version {ver} should be rejected (unreachable): {s}");
		}
	}
}
