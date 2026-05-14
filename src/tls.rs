use crate::error::{Result, SymphonyError};
use crate::mtls::SymphonyClientVerifier;
use rustls::ServerConfig;
use std::collections::HashMap;
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

/// Builds and deduplicates Arc<ServerConfig> instances.
/// Routes sharing identical cert + mTLS config share one allocation.
pub struct TlsConfigCache {
	// key: (cert_sha256, mtls_sha256_or_zeros) -> Arc<ServerConfig>
	cache: HashMap<([u8; 32], [u8; 32]), Arc<ServerConfig>>,
}

impl TlsConfigCache {
	pub fn new() -> Self {
		Self { cache: HashMap::new() }
	}

	pub fn get_or_build(
		&mut self,
		cert: &CertSpec,
		mtls: Option<&MtlsSpec>,
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

		let cache_key = (cert_key, mtls_key);
		if let Some(cfg) = self.cache.get(&cache_key) {
			return Ok(cfg.clone());
		}

		let cfg = build_server_config(cert, mtls)?;
		self.cache.insert(cache_key, cfg.clone());
		Ok(cfg)
	}
}

fn build_server_config(cert: &CertSpec, mtls: Option<&MtlsSpec>) -> Result<Arc<ServerConfig>> {
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

	let cfg = if let Some(m) = mtls {
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

	Ok(Arc::new(cfg))
}

fn sha256(data: &[u8]) -> [u8; 32] {
	let digest = ring::digest::digest(&ring::digest::SHA256, data);
	let mut out = [0u8; 32];
	out.copy_from_slice(digest.as_ref());
	out
}
