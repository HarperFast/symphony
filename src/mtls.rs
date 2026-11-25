use crate::metrics::ErrorKind;
use rustls::{server::danger::ClientCertVerifier, DistinguishedName};
use rustls_pki_types::{CertificateDer, UnixTime};
use std::sync::Arc;

/// Wraps WebPkiClientVerifier to allow optional client certificate requirement.
pub struct SymphonyClientVerifier {
	inner: Arc<dyn ClientCertVerifier>,
	require_cert: bool,
	/// Accept any presented chain inside the handshake, so a rejected client gets no alert;
	/// `verify_presented` is then the chain check, and every connection accepted through this
	/// verifier's config must pass it before anything reaches an upstream.
	defer_chain_check: bool,
}

impl SymphonyClientVerifier {
	pub fn build(
		ca_pem: &[u8],
		require_cert: bool,
		defer_chain_check: bool,
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
			.map_err(|e| {
				crate::error::SymphonyError::Config(format!("client verifier build failed: {e}"))
			})?;

		Ok(Arc::new(Self {
			inner,
			require_cert,
			defer_chain_check,
		}))
	}

	/// The chain check, over the chain a session carries: the one the client sent, or on a resumed
	/// session the one stored with it, which rustls never verifies again.
	pub fn verify_presented(
		&self,
		chain: Option<&[CertificateDer<'_>]>,
		now: UnixTime,
	) -> Result<(), rustls::Error> {
		match chain.and_then(<[_]>::split_first) {
			Some((end_entity, intermediates)) => self
				.inner
				.verify_client_cert(end_entity, intermediates, now)
				.map(|_| ()),
			None if self.require_cert => Err(rustls::Error::NoCertificatesPresented),
			None => Ok(()),
		}
	}
}

/// The error reason for a rejected client certificate, or `None` for any other TLS failure. A
/// server verifies no certificate but its clients', so every `InvalidCertificate` is one of theirs.
pub fn client_cert_rejection(err: &rustls::Error) -> Option<ErrorKind> {
	use rustls::CertificateError::{Expired, ExpiredContext};
	match err {
		rustls::Error::InvalidCertificate(Expired | ExpiredContext { .. }) => {
			Some(ErrorKind::ClientCertExpired)
		}
		rustls::Error::InvalidCertificate(_) => Some(ErrorKind::ClientCertUntrusted),
		rustls::Error::NoCertificatesPresented => Some(ErrorKind::ClientCertMissing),
		_ => None,
	}
}

impl std::fmt::Debug for SymphonyClientVerifier {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("SymphonyClientVerifier")
			.field("require_cert", &self.require_cert)
			.field("defer_chain_check", &self.defer_chain_check)
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
		if self.defer_chain_check {
			return Ok(rustls::server::danger::ClientCertVerified::assertion());
		}
		self.inner
			.verify_client_cert(end_entity, intermediates, now)
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

#[cfg(test)]
mod tests {
	use super::*;
	use crate::router::tests::CERT_A;
	use rustls::CertificateError;

	fn now() -> UnixTime {
		UnixTime::now()
	}

	/// Not a certificate at all, so the chain check rejects it however the trust anchors look.
	fn garbage() -> CertificateDer<'static> {
		CertificateDer::from(vec![0x30, 0x03, 0x02, 0x01, 0x01])
	}

	#[test]
	fn rejections_are_classified_by_reason() {
		let cert = |e| rustls::Error::InvalidCertificate(e);
		let expired_at = rustls::Error::InvalidCertificate(CertificateError::ExpiredContext {
			time: UnixTime::since_unix_epoch(std::time::Duration::from_secs(2)),
			not_after: UnixTime::since_unix_epoch(std::time::Duration::from_secs(1)),
		});
		let cases = [
			(
				cert(CertificateError::Expired),
				Some(ErrorKind::ClientCertExpired),
			),
			(expired_at, Some(ErrorKind::ClientCertExpired)),
			(
				cert(CertificateError::NotValidYet),
				Some(ErrorKind::ClientCertUntrusted),
			),
			(
				cert(CertificateError::UnknownIssuer),
				Some(ErrorKind::ClientCertUntrusted),
			),
			(
				cert(CertificateError::BadSignature),
				Some(ErrorKind::ClientCertUntrusted),
			),
			(
				rustls::Error::NoCertificatesPresented,
				Some(ErrorKind::ClientCertMissing),
			),
			(
				rustls::Error::PeerIncompatible(rustls::PeerIncompatible::NoCipherSuitesInCommon),
				None,
			),
			(rustls::Error::General("boom".into()), None),
		];
		for (err, expected) in cases {
			assert_eq!(client_cert_rejection(&err), expected, "{err:?}");
		}
	}

	#[test]
	fn deferring_changes_only_the_handshake_time_chain_check() {
		for required in [true, false] {
			let strict = SymphonyClientVerifier::build(CERT_A, required, false).unwrap();
			let deferring = SymphonyClientVerifier::build(CERT_A, required, true).unwrap();
			assert_eq!(
				strict.client_auth_mandatory(),
				deferring.client_auth_mandatory()
			);
			let hints = |v: &SymphonyClientVerifier| {
				v.root_hint_subjects()
					.iter()
					.map(|dn| dn.as_ref().to_vec())
					.collect::<Vec<_>>()
			};
			assert_eq!(hints(&strict), hints(&deferring));
			assert!(!hints(&strict).is_empty());
			assert_eq!(
				strict.supported_verify_schemes(),
				deferring.supported_verify_schemes()
			);

			assert!(strict.verify_client_cert(&garbage(), &[], now()).is_err());
			assert!(deferring.verify_client_cert(&garbage(), &[], now()).is_ok());
			let later = deferring.verify_presented(Some(&[garbage()]), now());
			assert!(matches!(later, Err(rustls::Error::InvalidCertificate(_))));
		}
	}

	#[test]
	fn no_certificate_passes_only_where_one_is_optional() {
		let required = SymphonyClientVerifier::build(CERT_A, true, true).unwrap();
		let optional = SymphonyClientVerifier::build(CERT_A, false, true).unwrap();
		for chain in [None, Some(&[][..])] {
			assert!(matches!(
				required.verify_presented(chain, now()),
				Err(rustls::Error::NoCertificatesPresented)
			));
			assert!(optional.verify_presented(chain, now()).is_ok());
		}
	}
}
