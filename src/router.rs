use crate::balancer::{UdsBalancer, UdsSlotSpec};
use crate::tls::{CertSpec, MtlsSpec, TlsConfigCache};
use arc_swap::ArcSwap;
use rustls::ServerConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_ns() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or(Duration::ZERO)
		.as_nanos() as u64
}

// ── Per-route global token bucket ─────────────────────────────────────────────

/// A route-global (not per-IP) token bucket that caps the rate of new
/// connections accepted for a single route.  Uses the same fixed-point ×1000
/// CAS pattern as `protection.rs`.
pub struct RouteTokenBucket {
	/// Token count in fixed-point ×1000.  Max = `burst_fp`.
	tokens: AtomicU32,
	last_refill_ns: AtomicU64,
	/// Tokens added per nanosecond (= cps / 1e9).
	rate_per_ns: f64,
	/// Bucket ceiling in fixed-point ×1000.
	burst_fp: u32,
}

impl RouteTokenBucket {
	pub fn new(cps: f64, burst: Option<f64>) -> Self {
		let burst_fp = ((burst.unwrap_or(cps)).max(1.0) * 1000.0) as u32;
		Self {
			tokens: AtomicU32::new(burst_fp),
			last_refill_ns: AtomicU64::new(now_ns()),
			rate_per_ns: cps / 1_000_000_000.0,
			burst_fp,
		}
	}

	/// Attempt to consume one token.  Returns `false` when the bucket is empty
	/// (caller should drop the connection).
	pub fn try_acquire(&self) -> bool {
		const ONE_TOKEN: u32 = 1000; // fixed-point ×1000 representation of 1 token

		// Refill: add tokens proportional to elapsed time since last refill.
		let now = now_ns();
		loop {
			let last = self.last_refill_ns.load(Ordering::Relaxed);
			let elapsed = now.saturating_sub(last);
			let refill = (elapsed as f64 * self.rate_per_ns * 1000.0) as u32;
			if refill == 0 {
				break;
			}
			let old = self.tokens.load(Ordering::Relaxed);
			let new = old.saturating_add(refill).min(self.burst_fp);
			if self.tokens
				.compare_exchange(old, new, Ordering::Relaxed, Ordering::Relaxed)
				.is_ok()
			{
				let _ = self.last_refill_ns.compare_exchange(
					last, now, Ordering::Relaxed, Ordering::Relaxed,
				);
				break;
			}
			// CAS lost a race — retry
		}

		// Consume one token.
		loop {
			let tokens = self.tokens.load(Ordering::Relaxed);
			if tokens < ONE_TOKEN {
				return false;
			}
			if self.tokens
				.compare_exchange(
					tokens,
					tokens - ONE_TOKEN,
					Ordering::Relaxed,
					Ordering::Relaxed,
				)
				.is_ok()
			{
				return true;
			}
		}
	}
}

// ── Source address forwarding mode ────────────────────────────────────────────

/// How the real client IP is communicated to the upstream.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SourceAddressMode {
	/// No source address forwarding.
	None,
	/// Send a PROXY protocol v1 header before any application data.
	ProxyProtocol,
	/// Parse the beginning of the HTTP request and insert an X-Forwarded-For header.
	XForwardedFor,
}

// ── Route destination ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub enum Destination {
	Tcp(SocketAddr),
	UdsSet(Arc<UdsBalancer>),
}

// ── A resolved route ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Route {
	pub destination: Destination,
	/// None = TLS passthrough (no termination)
	pub tls_config: Option<Arc<ServerConfig>>,
	pub terminate_tls: bool,
	pub suspended: bool,
	pub suspend_timeout: Duration,
	/// Optional global rate limiter for this route.
	pub rate_limiter: Option<Arc<RouteTokenBucket>>,
	/// How the real client IP is forwarded to the upstream.
	pub source_address_mode: SourceAddressMode,
}

// ── Route table ───────────────────────────────────────────────────────────────

pub struct RouteTable {
	exact: HashMap<Arc<str>, Route>,
	/// (suffix_without_star_dot, route) — "*.example.com" stored as "example.com"
	wildcard: Vec<(Arc<str>, Route)>,
	default: Option<Route>,
	/// All UdsBalancers that have at least one pid/tid-configured slot.
	/// Used by the CPU monitor task spawned in `proxy.rs::start()`.
	pub monitored_balancers: Vec<Arc<UdsBalancer>>,
}

impl RouteTable {
	pub fn resolve(&self, sni: Option<&str>) -> Option<&Route> {
		let Some(sni) = sni else {
			return self.default.as_ref();
		};

		// Exact match first
		if let Some(r) = self.exact.get(sni) {
			return Some(r);
		}

		// Wildcard: match exactly one left-most label against stored suffixes.
		// e.g. "foo.example.com" matches "*.example.com" but "a.b.example.com" does not.
		for (suffix, route) in &self.wildcard {
			if sni.len() > suffix.len() + 1 {
				let dot_pos = sni.len() - suffix.len() - 1;
				let rest = &sni[sni.len() - suffix.len()..];
				let prefix = &sni[..dot_pos];
				if !prefix.contains('.')
					&& rest == suffix.as_ref()
					&& sni.as_bytes()[dot_pos] == b'.'
				{
					return Some(route);
				}
			}
		}

		self.default.as_ref()
	}
}

// ── Builder / config types ────────────────────────────────────────────────────

/// Raw JS-provided upstream specification.
#[derive(Clone, Debug)]
pub enum UpstreamSpec {
	Tcp { host: String, port: u16 },
	Uds {
		paths: Vec<String>,
		/// PID per path (parallel vec, same length as `paths`).
		pids: Vec<Option<u32>>,
		/// TID per path (parallel vec, same length as `paths`).
		tids: Vec<Option<u32>>,
		ip_affinity: bool,
		affinity_ttl_ms: u64,
	},
}

/// Raw JS-provided route configuration.
#[derive(Clone, Debug)]
pub struct RouteSpec {
	pub sni: String,
	pub upstreams: Vec<UpstreamSpec>,
	pub terminate_tls: bool,
	pub cert_pem: Option<Vec<u8>>,
	pub key_pem: Option<Vec<u8>>,
	pub mtls_ca_pem: Option<Vec<u8>>,
	pub require_client_cert: bool,
	pub suspended: bool,
	pub suspend_timeout_ms: u64,
	/// Optional global rate limit (connections per second) for this route.
	pub max_cps: Option<f64>,
	/// Token bucket burst ceiling (defaults to `max_cps` if not set).
	pub burst: Option<f64>,
	/// How the real client IP is forwarded to the upstream.
	pub source_address_mode: SourceAddressMode,
	/// Advertise h2 in ALPN so clients can negotiate HTTP/2.
	pub http2: bool,
}

/// Listener-level fallback cert/mTLS spec.
#[derive(Clone, Debug)]
pub struct ListenerTlsSpec {
	pub cert_pem: Option<Vec<u8>>,
	pub key_pem: Option<Vec<u8>>,
	pub mtls_ca_pem: Option<Vec<u8>>,
	pub require_client_cert: bool,
}

impl ListenerTlsSpec {
	pub fn empty() -> Self {
		Self {
			cert_pem: None,
			key_pem: None,
			mtls_ca_pem: None,
			require_client_cert: true,
		}
	}
}

/// Build a RouteTable from a list of route specs and a listener-level fallback.
pub fn build_route_table(
	specs: &[RouteSpec],
	listener_tls: &ListenerTlsSpec,
) -> crate::error::Result<RouteTable> {
	let mut cache = TlsConfigCache::new();
	let mut exact: HashMap<Arc<str>, Route> = HashMap::new();
	let mut wildcard: Vec<(Arc<str>, Route)> = Vec::new();
	let mut monitored_balancers: Vec<Arc<UdsBalancer>> = Vec::new();

	for spec in specs {
		let route = build_route(spec, listener_tls, &mut cache)?;

		// Collect UdsBalancers that have pid/tid slots for the monitor task.
		if let Destination::UdsSet(ref bal) = route.destination {
			if bal.has_monitored_slots() {
				monitored_balancers.push(bal.clone());
			}
		}

		if spec.sni.starts_with("*.") {
			let suffix: Arc<str> = Arc::from(&spec.sni[2..]);
			wildcard.push((suffix, route));
		} else {
			let key: Arc<str> = Arc::from(spec.sni.as_str());
			exact.insert(key, route);
		}
	}

	Ok(RouteTable { exact, wildcard, default: None, monitored_balancers })
}

fn build_route(
	spec: &RouteSpec,
	listener_tls: &ListenerTlsSpec,
	cache: &mut TlsConfigCache,
) -> crate::error::Result<Route> {
	let tls_config = if spec.terminate_tls {
		let cert_pem = spec
			.cert_pem
			.as_deref()
			.or(listener_tls.cert_pem.as_deref())
			.ok_or_else(|| {
				crate::error::SymphonyError::Config(format!(
					"route '{}' has terminateTls=true but no cert provided",
					spec.sni
				))
			})?;
		let key_pem = spec
			.key_pem
			.as_deref()
			.or(listener_tls.key_pem.as_deref())
			.ok_or_else(|| {
				crate::error::SymphonyError::Config(format!(
					"route '{}' has terminateTls=true but no private key provided",
					spec.sni
				))
			})?;
		let cert_spec = CertSpec {
			cert_chain_pem: cert_pem.to_vec(),
			private_key_pem: key_pem.to_vec().into(),
		};

		let mtls_ca = spec
			.mtls_ca_pem
			.as_deref()
			.or(listener_tls.mtls_ca_pem.as_deref());
		let mtls_spec = mtls_ca.map(|ca| MtlsSpec {
			client_ca_pem: ca.to_vec(),
			require_client_cert: if spec.mtls_ca_pem.is_some() {
				spec.require_client_cert
			} else {
				listener_tls.require_client_cert
			},
		});

		Some(cache.get_or_build(&cert_spec, mtls_spec.as_ref(), spec.http2)?)
	} else {
		None
	};

	let destination = build_destination(spec)?;

	let rate_limiter = spec
		.max_cps
		.map(|cps| Arc::new(RouteTokenBucket::new(cps, spec.burst)));

	Ok(Route {
		destination,
		tls_config,
		terminate_tls: spec.terminate_tls,
		suspended: spec.suspended,
		suspend_timeout: Duration::from_millis(spec.suspend_timeout_ms.max(1)),
		rate_limiter,
		source_address_mode: spec.source_address_mode,
	})
}

fn build_destination(spec: &RouteSpec) -> crate::error::Result<Destination> {
	// Suspended routes or routes with no upstreams use a placeholder TCP dest
	// that is replaced by resolveConnection() before any data flows.
	if spec.suspended || spec.upstreams.is_empty() {
		return Ok(Destination::Tcp("127.0.0.1:1".parse().unwrap()));
	}

	match &spec.upstreams[0] {
		UpstreamSpec::Tcp { host, port } => {
			let addr: SocketAddr =
				format!("{host}:{port}").parse().map_err(crate::error::SymphonyError::AddrParse)?;
			Ok(Destination::Tcp(addr))
		}
		UpstreamSpec::Uds { .. } => {
			// Collect all UDS upstreams into a flat slot list.
			let mut slots: Vec<UdsSlotSpec> = Vec::new();
			let mut ip_affinity = false;
			let mut affinity_ttl_ms = 300_000u64;

			for u in &spec.upstreams {
				if let UpstreamSpec::Uds {
					paths,
					pids,
					tids,
					ip_affinity: aff,
					affinity_ttl_ms: ttl,
				} = u
				{
					for (i, path) in paths.iter().enumerate() {
						slots.push(UdsSlotSpec {
							path: path.clone(),
							pid: pids.get(i).copied().flatten(),
							tid: tids.get(i).copied().flatten(),
						});
					}
					ip_affinity = *aff;
					affinity_ttl_ms = *ttl;
				}
			}

			Ok(Destination::UdsSet(Arc::new(UdsBalancer::new(
				slots,
				ip_affinity,
				affinity_ttl_ms,
			))))
		}
	}
}

// ── Live route table holder ───────────────────────────────────────────────────

pub struct LiveRouteTable(pub ArcSwap<RouteTable>);

impl LiveRouteTable {
	pub fn new(table: RouteTable) -> Arc<Self> {
		Arc::new(Self(ArcSwap::new(Arc::new(table))))
	}

	pub fn swap(&self, table: RouteTable) {
		self.0.store(Arc::new(table));
	}
}
