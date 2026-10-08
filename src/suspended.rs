use crate::balancer::{UdsBalancer, UdsSlotSpec};
use crate::router::{Destination, ForwardFingerprint, RouteProtocol, SourceAddressMode};
use crate::tls::{CertSpec, MtlsSpec, TlsConfigCache};
use dashmap::DashMap;
use rustls::ServerConfig;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::oneshot;

/// The resolved route sent back from JS via `resolveConnection()`.
pub struct ResolvedRoute {
	pub destination: Destination,
	pub tls_config: Option<Arc<ServerConfig>>,
	pub terminate_tls: bool,
	pub source_address_mode: SourceAddressMode,
	pub forward_fingerprint: ForwardFingerprint,
	pub protocol: RouteProtocol,
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

	/// Whether `id` is still a live pending suspension. Lets `resolveConnection()` skip parsing
	/// and building a route (cert/TLS work included) for an id that has already timed out or was
	/// never valid — that work would be wasted, and any resulting error would be spurious, since
	/// `resolve()` already treats an unknown id as a silent no-op.
	pub fn contains(&self, id: u64) -> bool {
		self.pending.contains_key(&id)
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
	pub forward_fingerprint: ForwardFingerprint,
	pub http2: bool,
	pub protocol: RouteProtocol,
}

#[derive(Debug)]
pub enum ResolveUpstream {
	Tcp(std::net::SocketAddr),
	Uds {
		paths: Vec<String>,
		ip_affinity: bool,
		affinity_ttl_ms: u64,
	},
}

/// Build a `ResolvedRoute` from a `ResolveSpec`. `tls_cache` is the proxy's own, so every
/// resolution of one cert gets the same `ServerConfig` — and with it the session store and ticket
/// keys a returning client needs to resume.
pub fn build_resolved_route(
	spec: &ResolveSpec,
	tls_cache: &Mutex<TlsConfigCache>,
) -> crate::error::Result<ResolvedRoute> {
	let tls_config = if spec.terminate_tls {
		let cert_pem = spec.cert_pem.as_deref().ok_or_else(|| {
			crate::error::SymphonyError::Config(
				"resolveConnection: terminateTls=true requires cert".into(),
			)
		})?;
		let key_pem = spec.key_pem.as_deref().ok_or_else(|| {
			crate::error::SymphonyError::Config(
				"resolveConnection: terminateTls=true requires key".into(),
			)
		})?;

		let cert_spec = CertSpec {
			cert_chain_pem: cert_pem.to_vec(),
			private_key_pem: key_pem.to_vec().into(),
		};
		let mtls_spec = spec.mtls_ca_pem.as_deref().map(|ca| MtlsSpec {
			client_ca_pem: ca.to_vec(),
			require_client_cert: spec.require_client_cert,
		});

		// Poison recovery as in `update_config`.
		let mut cache = tls_cache.lock().unwrap_or_else(|e| e.into_inner());
		Some(cache.get_or_build(&cert_spec, mtls_spec.as_ref(), spec.http2)?)
	} else {
		None
	};

	let destination = match &spec.upstream {
		ResolveUpstream::Tcp(addr) => Destination::Tcp(*addr),
		ResolveUpstream::Uds {
			paths,
			ip_affinity,
			affinity_ttl_ms,
		} => {
			let slots = paths
				.iter()
				.map(|p| UdsSlotSpec {
					path: p.clone(),
					pid: None,
					tid: None,
				})
				.collect();
			Destination::UdsSet(Arc::new(UdsBalancer::new(
				slots,
				*ip_affinity,
				*affinity_ttl_ms,
			)))
		}
	};

	Ok(ResolvedRoute {
		destination,
		tls_config,
		terminate_tls: spec.terminate_tls,
		source_address_mode: spec.source_address_mode,
		forward_fingerprint: spec.forward_fingerprint,
		protocol: spec.protocol,
	})
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::router::tests::{CERT_A, KEY_A, KEY_B};
	use crate::router::{build_route_table, ListenerTlsSpec, RouteSpec};

	fn resolve_spec(key: &[u8]) -> ResolveSpec {
		ResolveSpec {
			upstream: ResolveUpstream::Tcp("127.0.0.1:9".parse().unwrap()),
			terminate_tls: true,
			cert_pem: Some(CERT_A.to_vec()),
			key_pem: Some(key.to_vec()),
			mtls_ca_pem: None,
			require_client_cert: false,
			source_address_mode: SourceAddressMode::None,
			forward_fingerprint: ForwardFingerprint::NONE,
			http2: false,
			protocol: RouteProtocol::Opaque,
		}
	}

	fn tls_config(spec: &ResolveSpec, cache: &Mutex<TlsConfigCache>) -> Arc<ServerConfig> {
		build_resolved_route(spec, cache)
			.expect("resolve")
			.tls_config
			.expect("terminating route")
	}

	/// A committed route-table reload, as `update_config` runs it.
	fn reload(cache: &Mutex<TlsConfigCache>, specs: &[RouteSpec]) -> crate::router::RouteTable {
		let mut cache = cache.lock().unwrap();
		let table =
			build_route_table(specs, &ListenerTlsSpec::empty(), None, &mut cache).expect("build");
		cache.retain_used();
		table
	}

	#[test]
	fn resolutions_of_one_cert_share_a_server_config() {
		let cache = Mutex::new(TlsConfigCache::new());
		let spec = resolve_spec(KEY_A);
		assert!(Arc::ptr_eq(
			&tls_config(&spec, &cache),
			&tls_config(&spec, &cache)
		));
	}

	// One config means one ticketer, so anything that changes what a resumed session may skip
	// (client auth, ALPN) must key a different one.
	#[test]
	fn tls_policy_keys_a_separate_server_config() {
		let cache = Mutex::new(TlsConfigCache::new());
		let plain = resolve_spec(KEY_A);
		let mut mtls_required = resolve_spec(KEY_A);
		mtls_required.mtls_ca_pem = Some(CERT_A.to_vec());
		mtls_required.require_client_cert = true;
		let mut mtls_optional = resolve_spec(KEY_A);
		mtls_optional.mtls_ca_pem = Some(CERT_A.to_vec());
		let mut h2 = resolve_spec(KEY_A);
		h2.http2 = true;

		let configs: Vec<_> = [&plain, &mtls_required, &mtls_optional, &h2]
			.into_iter()
			.map(|spec| tls_config(spec, &cache))
			.collect();
		for (i, a) in configs.iter().enumerate() {
			for b in &configs[i + 1..] {
				assert!(!Arc::ptr_eq(a, b));
			}
		}
	}

	#[test]
	fn a_resolution_shares_a_table_route_config_for_the_same_cert() {
		let cache = Mutex::new(TlsConfigCache::new());
		let route = crate::router::tests::tls_route("tenant.example.com", CERT_A, KEY_A);
		let table = reload(&cache, &[route]);
		let table_config = table
			.resolve(Some("tenant.example.com"))
			.and_then(|r| r.tls_config.clone())
			.expect("route config");
		assert!(Arc::ptr_eq(
			&table_config,
			&tls_config(&resolve_spec(KEY_A), &cache)
		));
	}

	#[test]
	fn a_held_resolved_config_survives_a_reload_and_an_idle_one_does_not() {
		let cache = Mutex::new(TlsConfigCache::new());
		let spec = resolve_spec(KEY_A);

		let held = tls_config(&spec, &cache);
		reload(&cache, &[]);
		assert!(
			Arc::ptr_eq(&held, &tls_config(&spec, &cache)),
			"a config a live connection holds must outlive the sweep"
		);

		drop(held);
		reload(&cache, &[]);
		assert!(
			cache.lock().unwrap().is_empty(),
			"no table or connection references it any more"
		);
	}

	#[test]
	fn a_failed_resolution_leaves_the_cache_usable() {
		let cache = Mutex::new(TlsConfigCache::new());
		assert!(build_resolved_route(&resolve_spec(KEY_B), &cache).is_err());
		let first = tls_config(&resolve_spec(KEY_A), &cache);
		assert!(Arc::ptr_eq(
			&first,
			&tls_config(&resolve_spec(KEY_A), &cache)
		));
		assert_eq!(cache.lock().unwrap().len(), 1);
	}
}
