use crate::balancer::{UdsBalancer, UdsSlotSpec};
use crate::router::{Destination, SourceAddressMode};
use dashmap::DashMap;
use rustls::ServerConfig;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::oneshot;

/// The resolved route sent back from JS via `resolveConnection()`.
pub struct ResolvedRoute {
	pub destination: Destination,
	pub tls_config: Option<Arc<ServerConfig>>,
	pub terminate_tls: bool,
	pub source_address_mode: SourceAddressMode,
}

/// Registry of suspended connections waiting for `resolveConnection()`.
pub struct SuspendedRegistry {
	pending: DashMap<u64, oneshot::Sender<Option<ResolvedRoute>>>,
	counter: AtomicU64,
}

impl SuspendedRegistry {
	pub fn new() -> Arc<Self> {
		Arc::new(Self {
			pending: DashMap::new(),
			counter: AtomicU64::new(1),
		})
	}

	/// Register a new suspended connection. Returns (id, receiver).
	/// The caller awaits the receiver; JS calls resolve() with the matching id.
	pub fn register(&self) -> (u64, oneshot::Receiver<Option<ResolvedRoute>>) {
		let id = self.counter.fetch_add(1, Ordering::Relaxed);
		let (tx, rx) = oneshot::channel();
		self.pending.insert(id, tx);
		(id, rx)
	}

	/// Resolve a suspended connection. Called from `resolveConnection()` on the JS side.
	/// Sending None closes the connection. Unknown or expired IDs are silently ignored.
	pub fn resolve(&self, id: u64, resolved: Option<ResolvedRoute>) {
		if let Some((_, tx)) = self.pending.remove(&id) {
			// Ignore send error — the waiting task may have timed out and dropped rx
			let _ = tx.send(resolved);
		}
	}

	/// Remove a pending entry (called on timeout before the receiver is dropped).
	pub fn remove(&self, id: u64) {
		self.pending.remove(&id);
	}

	/// Number of currently pending suspended connections.
	pub fn pending_count(&self) -> u64 {
		self.pending.len() as u64
	}
}

// ── JS-side resolver spec ─────────────────────────────────────────────────────

/// Parsed from the JS `route` argument passed to `resolveConnection()`.
#[derive(Debug)]
pub struct ResolveSpec {
	pub upstream: ResolveUpstream,
	pub terminate_tls: bool,
	pub cert_pem: Option<Vec<u8>>,
	pub key_pem: Option<Vec<u8>>,
	pub mtls_ca_pem: Option<Vec<u8>>,
	pub require_client_cert: bool,
	pub source_address_mode: SourceAddressMode,
	pub http2: bool,
}

#[derive(Debug)]
pub enum ResolveUpstream {
	Tcp(std::net::SocketAddr),
	Uds { paths: Vec<String>, ip_affinity: bool, affinity_ttl_ms: u64 },
}

/// Build a `ResolvedRoute` from a `ResolveSpec`.
pub fn build_resolved_route(spec: &ResolveSpec) -> crate::error::Result<ResolvedRoute> {
	use crate::tls::{CertSpec, MtlsSpec, TlsConfigCache};

	let tls_config = if spec.terminate_tls {
		let cert_pem = spec
			.cert_pem
			.as_deref()
			.ok_or_else(|| crate::error::SymphonyError::Config("resolveConnection: terminateTls=true requires cert".into()))?;
		let key_pem = spec
			.key_pem
			.as_deref()
			.ok_or_else(|| crate::error::SymphonyError::Config("resolveConnection: terminateTls=true requires key".into()))?;

		let cert_spec = CertSpec {
			cert_chain_pem: cert_pem.to_vec(),
			private_key_pem: key_pem.to_vec(),
		};
		let mtls_spec = spec.mtls_ca_pem.as_deref().map(|ca| MtlsSpec {
			client_ca_pem: ca.to_vec(),
			require_client_cert: spec.require_client_cert,
		});

		let mut cache = TlsConfigCache::new();
		Some(cache.get_or_build(&cert_spec, mtls_spec.as_ref(), spec.http2)?)
	} else {
		None
	};

	let destination = match &spec.upstream {
		ResolveUpstream::Tcp(addr) => Destination::Tcp(*addr),
		ResolveUpstream::Uds { paths, ip_affinity, affinity_ttl_ms } => {
			let slots = paths
				.iter()
				.map(|p| UdsSlotSpec { path: p.clone(), pid: None, tid: None })
				.collect();
			Destination::UdsSet(Arc::new(UdsBalancer::new(slots, *ip_affinity, *affinity_ttl_ms)))
		}
	};

	Ok(ResolvedRoute {
		destination,
		tls_config,
		terminate_tls: spec.terminate_tls,
		source_address_mode: spec.source_address_mode,
	})
}
