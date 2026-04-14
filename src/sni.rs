use tokio::net::TcpStream;

/// Information extracted from a TLS ClientHello via MSG_PEEK.
#[derive(Debug, Default)]
pub struct PeekInfo {
	/// SNI hostname, if present in the ClientHello.
	pub sni: Option<String>,
	/// JA3 fingerprint as a 32-char lowercase hex string.
	/// Empty string if the ClientHello could not be parsed.
	pub ja3: String,
}

/// Peek at the first 4096 bytes of the stream and parse the TLS ClientHello.
/// Does NOT consume any bytes from the stream.
pub async fn peek(stream: &TcpStream) -> PeekInfo {
	let mut buf = [0u8; 4096];
	let n = match stream.peek(&mut buf).await {
		Ok(n) => n,
		Err(_) => return PeekInfo::default(),
	};
	parse_client_hello(&buf[..n])
}

fn parse_client_hello(buf: &[u8]) -> PeekInfo {
	let mut p = Parser::new(buf);
	let Some(hello) = p.parse_client_hello() else {
		return PeekInfo::default();
	};
	let sni = extract_sni(&hello.extensions);
	let ja3 = compute_ja3(hello.legacy_version, &hello.cipher_suites, &hello.extensions);
	PeekInfo { sni, ja3 }
}

// ── TLS record / ClientHello structures ──────────────────────────────────────

struct ClientHello<'a> {
	legacy_version: u16,
	cipher_suites: &'a [u8],   // raw bytes, 2 bytes per suite
	extensions: &'a [u8],      // raw extension list bytes
}

struct Parser<'a> {
	buf: &'a [u8],
	pos: usize,
}

impl<'a> Parser<'a> {
	fn new(buf: &'a [u8]) -> Self {
		Self { buf, pos: 0 }
	}

	fn remaining(&self) -> usize {
		self.buf.len() - self.pos
	}

	fn read_u8(&mut self) -> Option<u8> {
		if self.remaining() < 1 {
			return None;
		}
		let v = self.buf[self.pos];
		self.pos += 1;
		Some(v)
	}

	fn read_u16(&mut self) -> Option<u16> {
		if self.remaining() < 2 {
			return None;
		}
		let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
		self.pos += 2;
		Some(v)
	}

	fn read_u24(&mut self) -> Option<u32> {
		if self.remaining() < 3 {
			return None;
		}
		let v = u32::from_be_bytes([0, self.buf[self.pos], self.buf[self.pos + 1], self.buf[self.pos + 2]]);
		self.pos += 3;
		Some(v)
	}

	fn read_bytes(&mut self, n: usize) -> Option<&'a [u8]> {
		if self.remaining() < n {
			return None;
		}
		let s = &self.buf[self.pos..self.pos + n];
		self.pos += n;
		Some(s)
	}

	fn skip(&mut self, n: usize) -> Option<()> {
		if self.remaining() < n {
			return None;
		}
		self.pos += n;
		Some(())
	}

	fn parse_client_hello(&mut self) -> Option<ClientHello<'a>> {
		// TLS record header: content_type(1) + legacy_record_version(2) + length(2)
		let content_type = self.read_u8()?;
		if content_type != 0x16 {
			return None; // not a Handshake record
		}
		self.skip(2)?; // legacy_record_version — ignore
		let _record_len = self.read_u16()?;

		// Handshake header: msg_type(1) + length(3)
		let msg_type = self.read_u8()?;
		if msg_type != 0x01 {
			return None; // not ClientHello
		}
		let _hs_len = self.read_u24()?;

		// ClientHello body
		let legacy_version = self.read_u16()?;

		// Random: 32 bytes
		self.skip(32)?;

		// Session ID: 1-byte length + data
		let session_id_len = self.read_u8()? as usize;
		self.skip(session_id_len)?;

		// Cipher Suites: 2-byte length + data (2 bytes per suite)
		let cs_len = self.read_u16()? as usize;
		let cipher_suites = self.read_bytes(cs_len)?;

		// Compression Methods: 1-byte length + data
		let cm_len = self.read_u8()? as usize;
		self.skip(cm_len)?;

		// Extensions: 2-byte length + data (may be absent or truncated in short peeks)
		if self.remaining() < 2 {
			return Some(ClientHello { legacy_version, cipher_suites, extensions: &[] });
		}
		let ext_len = self.read_u16()? as usize;
		// Use however many extension bytes are available (peek may be truncated)
		let available = ext_len.min(self.remaining());
		let extensions = self.read_bytes(available)?;

		Some(ClientHello { legacy_version, cipher_suites, extensions })
	}
}

// ── SNI extraction ────────────────────────────────────────────────────────────

fn extract_sni(extensions: &[u8]) -> Option<String> {
	let mut p = Parser::new(extensions);
	while p.remaining() >= 4 {
		let ext_type = p.read_u16()?;
		let ext_len = p.read_u16()? as usize;
		let ext_data = p.read_bytes(ext_len)?;

		if ext_type != 0x0000 {
			continue; // not SNI
		}

		// SNI extension: list_length(2) + entries
		let mut sp = Parser::new(ext_data);
		let _list_len = sp.read_u16()?;
		while sp.remaining() >= 3 {
			let name_type = sp.read_u8()?;
			let name_len = sp.read_u16()? as usize;
			let name_data = sp.read_bytes(name_len)?;
			if name_type == 0x00 {
				// host_name
				return String::from_utf8(name_data.to_vec()).ok();
			}
		}
	}
	None
}

// ── JA3 computation ───────────────────────────────────────────────────────────

/// Returns true if a u16 value is a GREASE value.
/// GREASE values follow the pattern 0x?A?A (RFC 8701).
fn is_grease(v: u16) -> bool {
	let lo = (v & 0x00FF) as u8;
	let hi = ((v >> 8) & 0xFF) as u8;
	lo == 0x0A && hi == lo
}

fn md5_hex(data: &[u8]) -> String {
	use md5::{Digest, Md5};
	let hash = Md5::digest(data);
	bytes_to_hex(&hash)
}

fn compute_ja3(legacy_version: u16, cipher_suites: &[u8], extensions: &[u8]) -> String {
	// Collect cipher suite values, skipping GREASE
	let ciphers: Vec<u16> = cipher_suites
		.chunks_exact(2)
		.map(|c| u16::from_be_bytes([c[0], c[1]]))
		.filter(|&v| !is_grease(v))
		.collect();

	let mut ext_types: Vec<u16> = Vec::new();
	let mut elliptic_curves: Vec<u16> = Vec::new();
	let mut ec_point_formats: Vec<u8> = Vec::new();

	let mut p = Parser::new(extensions);
	while p.remaining() >= 4 {
		let ext_type = match p.read_u16() {
			Some(v) => v,
			None => break,
		};
		let ext_len = match p.read_u16() {
			Some(v) => v as usize,
			None => break,
		};
		let ext_data = match p.read_bytes(ext_len) {
			Some(v) => v,
			None => break,
		};

		if is_grease(ext_type) {
			continue;
		}
		ext_types.push(ext_type);

		match ext_type {
			0x000A => {
				// supported_groups (elliptic curves)
				if ext_data.len() >= 2 {
					let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
					let curves = &ext_data[2..];
					for chunk in curves[..list_len.min(curves.len())].chunks_exact(2) {
						let v = u16::from_be_bytes([chunk[0], chunk[1]]);
						if !is_grease(v) {
							elliptic_curves.push(v);
						}
					}
				}
			}
			0x000B => {
				// ec_point_formats
				if !ext_data.is_empty() {
					let fmt_len = ext_data[0] as usize;
					for &b in &ext_data[1..1 + fmt_len.min(ext_data.len() - 1)] {
						ec_point_formats.push(b);
					}
				}
			}
			_ => {}
		}
	}

	// Build JA3 string: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
	let ja3_str = format!(
		"{},{},{},{},{}",
		legacy_version,
		join_u16(&ciphers),
		join_u16(&ext_types),
		join_u16(&elliptic_curves),
		join_u8(&ec_point_formats),
	);

	md5_hex(ja3_str.as_bytes())
}

fn join_u16(vals: &[u16]) -> String {
	vals.iter()
		.map(|v| v.to_string())
		.collect::<Vec<_>>()
		.join("-")
}

fn join_u8(vals: &[u8]) -> String {
	vals.iter()
		.map(|v| v.to_string())
		.collect::<Vec<_>>()
		.join("-")
}

fn bytes_to_hex(bytes: &[u8]) -> String {
	let mut s = String::with_capacity(bytes.len() * 2);
	for b in bytes {
		s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
		s.push(char::from_digit((b & 0x0F) as u32, 16).unwrap_or('0'));
	}
	s
}


#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_is_grease() {
		assert!(is_grease(0x0A0A));
		assert!(is_grease(0x1A1A));
		assert!(is_grease(0xFAFA));
		assert!(!is_grease(0x002F));
		assert!(!is_grease(0x0A0B));
	}

	#[test]
	fn test_bytes_to_hex() {
		let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
		assert_eq!(bytes_to_hex(&bytes), "deadbeef");
	}

	/// Feed a minimal synthetic ClientHello and verify SNI extraction.
	#[test]
	fn test_parse_sni() {
		// Build a minimal TLS 1.3 ClientHello with just an SNI extension.
		let hostname = b"example.com";
		let sni_ext_data = {
			let name_entry = {
				let mut v = vec![0x00u8]; // name_type = host_name
				let len = hostname.len() as u16;
				v.extend_from_slice(&len.to_be_bytes());
				v.extend_from_slice(hostname);
				v
			};
			let list_len = name_entry.len() as u16;
			let mut v = list_len.to_be_bytes().to_vec();
			v.extend_from_slice(&name_entry);
			v
		};
		let ext = {
			let mut v = vec![0x00, 0x00]; // ext type = SNI
			let len = sni_ext_data.len() as u16;
			v.extend_from_slice(&len.to_be_bytes());
			v.extend_from_slice(&sni_ext_data);
			v
		};
		let extensions_block = {
			let len = ext.len() as u16;
			let mut v = len.to_be_bytes().to_vec();
			v.extend_from_slice(&ext);
			v
		};

		let mut hello_body = vec![];
		hello_body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2
		hello_body.extend_from_slice(&[0u8; 32]); // random
		hello_body.push(0x00); // session_id length = 0
		hello_body.extend_from_slice(&[0x00, 0x02]); // cipher_suites length = 2
		hello_body.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
		hello_body.push(0x01); // compression_methods length = 1
		hello_body.push(0x00); // null compression
		hello_body.extend_from_slice(&extensions_block);

		let hs_len = hello_body.len() as u32;
		let mut hs = vec![0x01u8]; // msg_type = ClientHello
		hs.push(((hs_len >> 16) & 0xFF) as u8);
		hs.push(((hs_len >> 8) & 0xFF) as u8);
		hs.push((hs_len & 0xFF) as u8);
		hs.extend_from_slice(&hello_body);

		let mut record = vec![0x16u8, 0x03, 0x01]; // content_type, version
		let record_len = hs.len() as u16;
		record.extend_from_slice(&record_len.to_be_bytes());
		record.extend_from_slice(&hs);

		let info = parse_client_hello(&record);
		assert_eq!(info.sni.as_deref(), Some("example.com"));
		assert!(!info.ja3.is_empty());
		assert_eq!(info.ja3.len(), 32);
	}
}
