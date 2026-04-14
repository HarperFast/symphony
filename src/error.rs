use thiserror::Error;

#[derive(Error, Debug)]
pub enum SymphonyError {
	#[error("TLS error: {0}")]
	Tls(#[from] rustls::Error),

	#[error("I/O error: {0}")]
	Io(#[from] std::io::Error),

	#[error("No route for SNI '{0}'")]
	NoRoute(String),

	#[error("Config error: {0}")]
	Config(String),

	#[error("Address parse error: {0}")]
	AddrParse(#[from] std::net::AddrParseError),
}

impl From<SymphonyError> for napi::Error {
	fn from(e: SymphonyError) -> Self {
		napi::Error::from_reason(e.to_string())
	}
}

pub type Result<T> = std::result::Result<T, SymphonyError>;
