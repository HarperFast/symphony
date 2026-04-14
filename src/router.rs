use crate::balancer::UdsBalancer;
use crate::tls::{CertSpec, MtlsSpec, TlsConfigCache};
use arc_swap::ArcSwap;
use rustls::ServerConfig;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

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
}

// ── Route table ───────────────────────────────────────────────────────────────

pub struct RouteTable {
	exact: HashMap<Arc<str>, Route>,
	/// (suffix_without_star_dot, route) — "*.example.com" stored as "example.com"
	wildcard: Vec<(Arc<str>, Route)>,
	default: Option<Route>,
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

		// Wildcard: match left-most label against stored suffixes
		// e.g. sni="foo.example.com" matches suffix="example.com"
		for (suffix, route) in &self.wildcard {
			if sni.len() > suffix.len() + 1 {
				let rest = &sni[sni.len() - suffix.len()..];
				let dot_pos = sni.len() - suffix.len() - 1;
				if rest == suffix.as_ref() && sni.as_bytes()[dot_pos] == b'.' {
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
	Uds { paths: Vec<String>, ip_affinity: bool, affinity_ttl_ms: u64 },
}

/// Raw JS-provided route configuration.
#[derive(Clone, Debug)]
pub struct RouteSpec {
	pub sni: String,
	pub upstreams: Vec<UpstreamSpec>,
	pub terminate_tls: bool,
	pub cert_pem: Option<Vec<u8>>,       // cert chain PEM bytes
	pub key_pem: Option<Vec<u8>>,        // private key PEM bytes
	pub mtls_ca_pem: Option<Vec<u8>>,    // CA cert PEM for mTLS
	pub require_client_cert: bool,
	pub suspended: bool,
	pub suspend_timeout_ms: u64,
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

	for spec in specs {
		let route = build_route(spec, listener_tls, &mut cache)?;

		if spec.sni.starts_with("*.") {
			// Store suffix without the leading "*."
			let suffix: Arc<str> = Arc::from(&spec.sni[2..]);
			wildcard.push((suffix, route));
		} else {
			let key: Arc<str> = Arc::from(spec.sni.as_str());
			exact.insert(key, route);
		}
	}

	Ok(RouteTable { exact, wildcard, default: None })
}

fn build_route(
	spec: &RouteSpec,
	listener_tls: &ListenerTlsSpec,
	cache: &mut TlsConfigCache,
) -> crate::error::Result<Route> {
	// Resolve TLS config: route cert takes priority over listener default
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
			private_key_pem: key_pem.to_vec(),
		};

		// mTLS: route-level overrides listener-level
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

		Some(cache.get_or_build(&cert_spec, mtls_spec.as_ref())?)
	} else {
		None
	};

	// Build destination
	let destination = build_destination(spec)?;

	Ok(Route {
		destination,
		tls_config,
		terminate_tls: spec.terminate_tls,
		suspended: spec.suspended,
		suspend_timeout: Duration::from_millis(spec.suspend_timeout_ms.max(1)),
	})
}

fn build_destination(spec: &RouteSpec) -> crate::error::Result<Destination> {
	// For suspended routes with no upstreams, use a placeholder TCP dest.
	// It will be replaced by resolveConnection() before any connection is made.
	if spec.suspended || spec.upstreams.is_empty() {
		return Ok(Destination::Tcp("127.0.0.1:1".parse().unwrap()));
	}

	match &spec.upstreams[0] {
		UpstreamSpec::Tcp { host, port } => {
			let addr: SocketAddr = format!("{host}:{port}").parse().map_err(crate::error::SymphonyError::AddrParse)?;
			Ok(Destination::Tcp(addr))
		}
		UpstreamSpec::Uds { .. } => {
			// Collect all UDS paths from all upstreams
			let mut paths = Vec::new();
			let mut ip_affinity = false;
			let mut affinity_ttl_ms = 300_000u64;
			for u in &spec.upstreams {
				if let UpstreamSpec::Uds { paths: p, ip_affinity: aff, affinity_ttl_ms: ttl } = u {
					paths.extend_from_slice(p);
					ip_affinity = *aff;
					affinity_ttl_ms = *ttl;
				}
			}
			Ok(Destination::UdsSet(Arc::new(UdsBalancer::new(paths, ip_affinity, affinity_ttl_ms))))
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
