use rustls::{
	server::danger::ClientCertVerifier,
	DistinguishedName,
};
use rustls_pki_types::{CertificateDer, UnixTime};
use std::sync::Arc;

/// Wraps WebPkiClientVerifier to allow optional client certificate requirement.
pub struct SymphonyClientVerifier {
	inner: Arc<dyn ClientCertVerifier>,
	require_cert: bool,
}

impl SymphonyClientVerifier {
	pub fn build(
		ca_pem: &[u8],
		require_cert: bool,
	) -> crate::error::Result<Arc<Self>> {
		let mut root_store = rustls::RootCertStore::empty();
		let mut reader = std::io::BufReader::new(ca_pem);
		for cert in rustls_pemfile::certs(&mut reader) {
			root_store
				.add(cert.map_err(|e| {
					crate::error::SymphonyError::Config(format!("invalid CA cert: {e}"))
				})?)
				.map_err(|e| {
					crate::error::SymphonyError::Config(format!("failed to add CA cert: {e}"))
				})?;
		}

		let inner = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
			.build()
			.map_err(|e| crate::error::SymphonyError::Config(format!("client verifier build failed: {e}")))?;

		Ok(Arc::new(Self { inner, require_cert }))
	}
}

impl std::fmt::Debug for SymphonyClientVerifier {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SymphonyClientVerifier")
			.field("require_cert", &self.require_cert)
			.finish()
	}
}

impl ClientCertVerifier for SymphonyClientVerifier {
	fn client_auth_mandatory(&self) -> bool {
		self.require_cert
	}

	fn root_hint_subjects(&self) -> &[DistinguishedName] {
		self.inner.root_hint_subjects()
	}

	fn verify_client_cert(
		&self,
		end_entity: &CertificateDer<'_>,
		intermediates: &[CertificateDer<'_>],
		now: UnixTime,
	) -> std::result::Result<rustls::server::danger::ClientCertVerified, rustls::Error> {
		self.inner.verify_client_cert(end_entity, intermediates, now)
	}

	fn verify_tls12_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		self.inner.verify_tls12_signature(message, cert, dss)
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer<'_>,
		dss: &rustls::DigitallySignedStruct,
	) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
		self.inner.verify_tls13_signature(message, cert, dss)
	}

	fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
		self.inner.supported_verify_schemes()
	}
}
