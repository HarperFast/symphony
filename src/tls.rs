use crate::error::{Result, SymphonyError};
use crate::mtls::SymphonyClientVerifier;
use rustls::ServerConfig;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use zeroize::Zeroizing;

/// Inputs for building a ServerConfig, used as a deduplication key.
#[derive(Debug)]
pub struct CertSpec {
	pub cert_chain_pem: Vec<u8>,
	/// Automatically zeroed on drop via `Zeroizing`.
	pub private_key_pem: Zeroizing<Vec<u8>>,
}

#[derive(Debug)]
pub struct MtlsSpec {
	pub client_ca_pem: Vec<u8>,
	pub require_client_cert: bool,
}

/// key: (cert_sha256, mtls_sha256_or_zeros, http2)
type CacheKey = ([u8; 32], [u8; 32], bool);

/// Builds and deduplicates Arc<ServerConfig> instances.
/// Routes sharing identical cert + mTLS config share one allocation.
///
/// The cache **outlives a single route-table build** — it is owned by the proxy and threaded
/// through every `build_route_table`. That is load-bearing for TLS session resumption, not just
/// an allocation saving: each `ServerConfig` owns its own session store and ticket keys (see
/// `build_server_config`), so minting a new one for an unchanged cert silently invalidates every
/// outstanding client ticket. Reloads are frequent — a route add/remove or an on-disk cert
/// renewal rebuilds the whole table — so a per-build cache means clients almost never get to
/// resume. Keying on the cert bytes gives exactly the right lifetime: session state survives as
/// long as the cert it was issued under, and rotating a cert retires it.
pub struct TlsConfigCache {
	cache: HashMap<CacheKey, Arc<ServerConfig>>,
	/// Keys touched since the last `retain_used()` — the mark half of mark-and-sweep.
	used: HashSet<CacheKey>,
}

impl TlsConfigCache {
	pub fn new() -> Self {
		Self { cache: HashMap::new(), used: HashSet::new() }
	}

	/// Drop every entry not requested since the previous sweep, retiring rotated-out certs.
	/// Callers run this once they *commit* the table they just built — see `build_route_table`.
	pub fn retain_used(&mut self) {
		let used = std::mem::take(&mut self.used);
		self.cache.retain(|k, _| used.contains(k));
	}

	/// Number of live `ServerConfig`s held.
	pub fn len(&self) -> usize {
		self.cache.len()
	}

	pub fn is_empty(&self) -> bool {
		self.cache.is_empty()
	}

	pub fn get_or_build(
		&mut self,
		cert: &CertSpec,
		mtls: Option<&MtlsSpec>,
		http2: bool,
	) -> Result<Arc<ServerConfig>> {
		// Hash both chain and private key so routes sharing a cert but using different
		// keys (e.g. mid-rotation) get distinct ServerConfig allocations.
		let cert_key = sha256(&[cert.cert_chain_pem.as_slice(), cert.private_key_pem.as_slice()].concat());
		let mtls_key = mtls
			.map(|m| {
				let mut buf = m.client_ca_pem.clone();
				buf.push(m.require_client_cert as u8);
				sha256(&buf)
			})
			.unwrap_or([0u8; 32]);

		let cache_key = (cert_key, mtls_key, http2);
		if let Some(cfg) = self.cache.get(&cache_key) {
			// Mark before returning: a hit is exactly as much "still in use" as a miss.
			self.used.insert(cache_key);
			return Ok(cfg.clone());
		}

		let cfg = build_server_config(cert, mtls, http2)?;
		self.cache.insert(cache_key, cfg.clone());
		self.used.insert(cache_key);
		Ok(cfg)
	}
}

fn build_server_config(cert: &CertSpec, mtls: Option<&MtlsSpec>, http2: bool) -> Result<Arc<ServerConfig>> {
	// Parse certificate chain
	let certs: Vec<_> = {
		let mut reader = std::io::BufReader::new(cert.cert_chain_pem.as_slice());
		rustls_pemfile::certs(&mut reader)
			.collect::<std::result::Result<Vec<_>, _>>()
			.map_err(|e| SymphonyError::Config(format!("invalid cert chain PEM: {e}")))?
	};
	if certs.is_empty() {
		return Err(SymphonyError::Config("cert chain PEM contains no certificates".into()));
	}

	// Parse private key
	let key = {
		let mut reader = std::io::BufReader::new(cert.private_key_pem.as_slice());
		rustls_pemfile::private_key(&mut reader)
			.map_err(|e| SymphonyError::Config(format!("invalid private key PEM: {e}")))?
			.ok_or_else(|| SymphonyError::Config("private key PEM contains no key".into()))?
	};

	let mut cfg = if let Some(m) = mtls {
		let verifier = SymphonyClientVerifier::build(&m.client_ca_pem, m.require_client_cert)?;
		ServerConfig::builder()
			.with_client_cert_verifier(verifier)
			.with_single_cert(certs, key)
			.map_err(SymphonyError::Tls)?
	} else {
		ServerConfig::builder()
			.with_no_client_auth()
			.with_single_cert(certs, key)
			.map_err(SymphonyError::Tls)?
	};

	// Enable TLS session resumption.
	//
	// rustls defaults to NeverProducesTickets (no TLS 1.3 tickets) and
	// NoServerSessionStorage (no TLS 1.2 session IDs). Without session
	// resumption, every new connection requires a full TLS handshake (~2ms).
	// Clients like Node.js cache session tickets and reuse them, cutting
	// handshake cost to ~0.1ms for resumed sessions.
	//
	// - session_storage: handles TLS 1.2 session ID resumption.
	// - ticketer: handles TLS 1.3 PSK-based session ticket resumption (primary
	//   path for modern clients).
	//
	// Both live *on this ServerConfig*: the cache entries and the ticketer's random keys die
	// with it. Rebuilding a config for an unchanged cert therefore looks like a no-op but
	// invalidates every ticket already handed out — which is why TlsConfigCache is owned by the
	// proxy and survives route-table rebuilds instead of being created per build. Keep them
	// per-config rather than process-global: a ticket minted under one tenant's cert should not
	// be resumable against another tenant's route.
	if http2 {
		cfg.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
	}

	cfg.session_storage = rustls::server::ServerSessionMemoryCache::new(1024);
	cfg.ticketer = rustls::crypto::ring::Ticketer::new()
		.map_err(SymphonyError::Tls)?;

	Ok(Arc::new(cfg))
}

fn sha256(data: &[u8]) -> [u8; 32] {
	let digest = ring::digest::digest(&ring::digest::SHA256, data);
	let mut out = [0u8; 32];
	out.copy_from_slice(digest.as_ref());
	out
}
