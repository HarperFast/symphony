use tokio::net::TcpStream;

/// Information extracted from a TLS ClientHello via MSG_PEEK.
#[derive(Debug, Default)]
pub struct PeekInfo {
	/// SNI hostname, if present in the ClientHello.
	pub sni: Option<String>,
	/// JA3 fingerprint as a 32-char lowercase hex string.
	/// Empty string if the ClientHello could not be parsed.
	pub ja3: String,
	/// JA4 fingerprint (core TLS only — BSD-licensed; JA4+ variants not implemented,
	/// FoxIO proprietary license). Format: t<ver><sni><cc><ec><alpn>_<sha256/12>_<sha256/12>.
	/// Empty string if the ClientHello could not be parsed.
	pub ja4: String,
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
	let sni = extract_sni(hello.extensions);
	let ja3 = compute_ja3(hello.legacy_version, hello.cipher_suites, hello.extensions);
	let ja4 = compute_ja4(hello.legacy_version, hello.cipher_suites, hello.extensions);
	PeekInfo { sni, ja3, ja4 }
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
				// host_name — normalize and validate per RFC 6066 §3
				let raw = String::from_utf8(name_data.to_vec()).ok()?;
				// Trim trailing dot (absolute domain name form)
				let sni = raw.trim_end_matches('.').to_string();
				// Reject empty, oversized, or structurally invalid values
				if sni.is_empty() || sni.len() > 253 || sni.contains(':') || sni.contains('/') {
					return None;
				}
				return Some(sni);
			}
		}
	}
	None
}

// ── JA3 computation ───────────────────────────────────────────────────────────

/// Returns true if a u16 value is a GREASE value (RFC 8701).
/// GREASE values are 0x?A?A: both bytes are equal and the low nibble is 0xA.
/// That gives 16 values: 0x0A0A, 0x1A1A, 0x2A2A, ..., 0xFAFA.
fn is_grease(v: u16) -> bool {
	let lo = (v & 0x00FF) as u8;
	let hi = ((v >> 8) & 0xFF) as u8;
	// GREASE values are 0x0A0A, 0x1A1A, ... 0xFAFA: both bytes equal, low nibble 0xA.
	hi == lo && (lo & 0x0F) == 0x0A
}

fn md5_hex(data: &[u8]) -> String {
	use md5::{Digest, Md5};
	let hash = Md5::digest(data);
	bytes_to_hex(&hash)
}

fn sha256_hex12(data: &[u8]) -> String {
	use sha2::{Digest, Sha256};
	let hash = Sha256::digest(data);
	bytes_to_hex(&hash[..6]) // 6 bytes = 12 hex chars
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

// ── JA4 computation ───────────────────────────────────────────────────────────
//
// JA4 is a BSD-licensed TLS client fingerprint (core TLS only).
// JA4S, JA4H, JA4SSH, and all other JA4+ variants are NOT implemented here —
// those variants carry a FoxIO proprietary license that is incompatible with
// commercial distribution.
//
// Spec: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
// Format: t<ver><sni><cc><ec><alpn>_<ciphers-sha256/12>_<exts-sha256/12>

fn compute_ja4(legacy_version: u16, cipher_suites: &[u8], extensions: &[u8]) -> String {
	// Parse extensions in a single pass.
	let mut ext_ids: Vec<u16> = Vec::new(); // all non-GREASE ext types
	let mut supported_versions: Vec<u16> = Vec::new();
	let mut alpn_first: Option<Vec<u8>> = None;
	let mut sig_algs: Vec<u16> = Vec::new();
	let mut has_sig_algs = false;

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
		ext_ids.push(ext_type);

		match ext_type {
			0x002B => {
				// supported_versions: list_len(1) + [version(2)]*
				if let Some((&list_len, rest)) = ext_data.split_first() {
					for chunk in rest[..(list_len as usize).min(rest.len())].chunks_exact(2) {
						let v = u16::from_be_bytes([chunk[0], chunk[1]]);
						if !is_grease(v) {
							supported_versions.push(v);
						}
					}
				}
			}
			0x0010 => {
				// ALPN: protocol_name_list_len(2) + [proto_len(1) + proto]*
				if ext_data.len() >= 2 {
					let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
					let list = &ext_data[2..2 + list_len.min(ext_data.len().saturating_sub(2))];
					if !list.is_empty() {
						let proto_len = list[0] as usize;
						if proto_len > 0 && 1 + proto_len <= list.len() {
							alpn_first = Some(list[1..1 + proto_len].to_vec());
						}
					}
				}
			}
			0x000D => {
				// signature_algorithms: list_len(2) + [alg(2)]*
				has_sig_algs = true;
				if ext_data.len() >= 2 {
					let list_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
					let algs = &ext_data[2..];
					for chunk in algs[..list_len.min(algs.len())].chunks_exact(2) {
						sig_algs.push(u16::from_be_bytes([chunk[0], chunk[1]]));
					}
				}
			}
			_ => {}
		}
	}

	// TLS version: max of supported_versions if present, else legacy_version.
	let tls_version = supported_versions.iter().copied().max().unwrap_or(legacy_version);
	let ver_str = match tls_version {
		0x0304 => "13",
		0x0303 => "12",
		0x0302 => "11",
		0x0301 => "10",
		_ => "00",
	};

	// SNI indicator: keyed on the SNI extension being present, per spec — not on whether
	// symphony's own hostname validation accepted its value.
	let sni_char = if ext_ids.contains(&0x0000) { 'd' } else { 'i' };

	// Cipher count: GREASE excluded, capped at 99.
	let cipher_count = cipher_suites
		.chunks_exact(2)
		.filter(|c| !is_grease(u16::from_be_bytes([c[0], c[1]])))
		.count()
		.min(99);

	// Extension count: all non-GREASE extensions including SNI (0) and ALPN (16), capped at 99.
	let ext_count = ext_ids.len().min(99);

	// ALPN first and last character of the first protocol value.
	// Non-alphanumeric characters are replaced with '9'; result is lowercase.
	let alpn_chars: String = match &alpn_first {
		None => "00".to_string(),
		Some(proto) if proto.is_empty() => "00".to_string(),
		Some(proto) => {
			let to_alnum = |b: u8| -> char {
				let c = b as char;
				if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { '9' }
			};
			format!("{}{}", to_alnum(proto[0]), to_alnum(proto[proto.len() - 1]))
		}
	};

	// Part A: 10 chars — t<ver><sni><cc><ec><alpn>
	let part_a = format!("t{ver_str}{sni_char}{cipher_count:02}{ext_count:02}{alpn_chars}");

	// Part B: SHA-256/12 of sorted 4-hex cipher list (GREASE excluded).
	let mut ciphers: Vec<u16> = cipher_suites
		.chunks_exact(2)
		.map(|c| u16::from_be_bytes([c[0], c[1]]))
		.filter(|&v| !is_grease(v))
		.collect();
	ciphers.sort_unstable();
	let part_b = if ciphers.is_empty() {
		"000000000000".to_string()
	} else {
		let cipher_str = ciphers.iter().map(|v| format!("{v:04x}")).collect::<Vec<_>>().join(",");
		sha256_hex12(cipher_str.as_bytes())
	};

	// Part C: SHA-256/12 of (sorted ext IDs, GREASE/SNI/ALPN excluded) optionally
	// followed by '_' + unsorted signature algorithms from ext 13.
	let mut ext_for_hash: Vec<u16> = ext_ids
		.iter()
		.filter(|&&t| t != 0x0000 && t != 0x0010) // remove SNI and ALPN
		.copied()
		.collect();
	ext_for_hash.sort_unstable();
	let ext_str = ext_for_hash.iter().map(|v| format!("{v:04x}")).collect::<Vec<_>>().join(",");

	let hash_input = if has_sig_algs {
		let sig_str = sig_algs.iter().map(|v| format!("{v:04x}")).collect::<Vec<_>>().join(",");
		format!("{ext_str}_{sig_str}")
	} else {
		ext_str
	};

	let part_c = if hash_input.is_empty() {
		"000000000000".to_string()
	} else {
		sha256_hex12(hash_input.as_bytes())
	};

	format!("{part_a}_{part_b}_{part_c}")
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

	// ── helpers for building synthetic ClientHellos ───────────────────────────

	fn make_extension(ext_type: u16, data: &[u8]) -> Vec<u8> {
		let mut v = Vec::new();
		v.extend_from_slice(&ext_type.to_be_bytes());
		v.extend_from_slice(&(data.len() as u16).to_be_bytes());
		v.extend_from_slice(data);
		v
	}

	fn make_sni_ext(hostname: &[u8]) -> Vec<u8> {
		// SNI: list_len(2) + [name_type(1) + name_len(2) + name]*
		let mut entry = vec![0x00u8]; // name_type = host_name
		entry.extend_from_slice(&(hostname.len() as u16).to_be_bytes());
		entry.extend_from_slice(hostname);
		let mut data = (entry.len() as u16).to_be_bytes().to_vec();
		data.extend_from_slice(&entry);
		make_extension(0x0000, &data)
	}

	fn make_supported_versions_ext(versions: &[u16]) -> Vec<u8> {
		// supported_versions: list_len(1) + [version(2)]*
		let mut data = vec![(versions.len() * 2) as u8];
		for &v in versions {
			data.extend_from_slice(&v.to_be_bytes());
		}
		make_extension(0x002B, &data)
	}

	fn make_alpn_ext(protos: &[&[u8]]) -> Vec<u8> {
		// ALPN: list_len(2) + [proto_len(1) + proto]*
		let mut list = Vec::new();
		for proto in protos {
			list.push(proto.len() as u8);
			list.extend_from_slice(proto);
		}
		let mut data = (list.len() as u16).to_be_bytes().to_vec();
		data.extend_from_slice(&list);
		make_extension(0x0010, &data)
	}

	fn make_sig_algs_ext(algs: &[u16]) -> Vec<u8> {
		// signature_algorithms: list_len(2) + [alg(2)]*
		let mut data = ((algs.len() * 2) as u16).to_be_bytes().to_vec();
		for &alg in algs {
			data.extend_from_slice(&alg.to_be_bytes());
		}
		make_extension(0x000D, &data)
	}

	fn make_client_hello(
		legacy_version: u16,
		ciphers: &[u16],
		exts: &[Vec<u8>],
	) -> Vec<u8> {
		let mut body = Vec::new();
		body.extend_from_slice(&legacy_version.to_be_bytes());
		body.extend_from_slice(&[0u8; 32]); // random
		body.push(0x00); // session_id length = 0
		let cs_len = (ciphers.len() * 2) as u16;
		body.extend_from_slice(&cs_len.to_be_bytes());
		for &c in ciphers {
			body.extend_from_slice(&c.to_be_bytes());
		}
		body.push(0x01); // compression methods length
		body.push(0x00); // null compression
		let ext_bytes: Vec<u8> = exts.iter().flat_map(|e| e.clone()).collect();
		body.extend_from_slice(&(ext_bytes.len() as u16).to_be_bytes());
		body.extend_from_slice(&ext_bytes);

		let hs_len = body.len() as u32;
		let mut hs = vec![0x01u8]; // ClientHello msg_type
		hs.push(((hs_len >> 16) & 0xFF) as u8);
		hs.push(((hs_len >> 8) & 0xFF) as u8);
		hs.push((hs_len & 0xFF) as u8);
		hs.extend_from_slice(&body);

		let mut record = vec![0x16u8, 0x03, 0x01];
		record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
		record.extend_from_slice(&hs);
		record
	}

	// ── is_grease ────────────────────────────────────────────────────────────

	#[test]
	fn test_is_grease() {
		// All 16 GREASE values (RFC 8701): 0x?A?A where both bytes equal and nibble=0xA
		for n in 0u16..=0xF {
			let v = ((n << 4 | 0xA) as u16) << 8 | (n << 4 | 0xA) as u16;
			assert!(is_grease(v), "expected is_grease(0x{v:04X})");
		}
		// Non-GREASE: bytes differ
		assert!(!is_grease(0x0A1A), "0x0A1A: bytes differ");
		assert!(!is_grease(0x1A0A), "0x1A0A: bytes differ");
		// Non-GREASE: low nibble not 0xA
		assert!(!is_grease(0x0B0B), "0x0B0B: nibble 0xB");
		assert!(!is_grease(0x0000), "0x0000");
		assert!(!is_grease(0xFFFF), "0xFFFF");
		assert!(!is_grease(0x002F), "real cipher");
		assert!(!is_grease(0x0A0B), "0x0A0B: bytes differ");
	}

	#[test]
	fn test_bytes_to_hex() {
		let bytes = [0xDE, 0xAD, 0xBE, 0xEF];
		assert_eq!(bytes_to_hex(&bytes), "deadbeef");
	}

	// ── JA4 structural tests ─────────────────────────────────────────────────

	#[test]
	fn test_ja4_format() {
		// Basic format: 3 parts separated by '_', lengths 10/12/12.
		let hello = make_client_hello(
			0x0303,
			&[0x1301],
			&[make_sni_ext(b"example.com")],
		);
		let info = parse_client_hello(&hello);
		assert!(!info.ja4.is_empty(), "JA4 should not be empty");
		let parts: Vec<&str> = info.ja4.split('_').collect();
		assert_eq!(parts.len(), 3, "JA4 must have 3 '_'-separated parts: {}", info.ja4);
		assert_eq!(parts[0].len(), 10, "Part A must be 10 chars: {}", info.ja4);
		assert_eq!(parts[1].len(), 12, "Part B must be 12 hex chars: {}", info.ja4);
		assert_eq!(parts[2].len(), 12, "Part C must be 12 hex chars: {}", info.ja4);
	}

	#[test]
	fn test_ja4_version_from_supported_versions() {
		// supported_versions = [0x0304] overrides legacy_version 0x0303 → "13"
		let hello = make_client_hello(
			0x0303,
			&[0x1301],
			&[
				make_sni_ext(b"test"),
				make_supported_versions_ext(&[0x0304]),
			],
		);
		let info = parse_client_hello(&hello);
		assert!(info.ja4.starts_with("t13"), "should use supported_versions: {}", info.ja4);
	}

	#[test]
	fn test_ja4_version_fallback() {
		// No supported_versions → fall back to legacy_version 0x0303 → "12"
		let hello = make_client_hello(
			0x0303,
			&[0x1301],
			&[make_sni_ext(b"test")],
		);
		let info = parse_client_hello(&hello);
		assert!(info.ja4.starts_with("t12"), "should fall back to legacy version: {}", info.ja4);
	}

	#[test]
	fn test_ja4_sni_indicator() {
		// SNI present → 'd'; absent → 'i' (4th char of JA4).
		let with_sni = make_client_hello(0x0303, &[0x1301], &[make_sni_ext(b"test")]);
		let without_sni = make_client_hello(0x0303, &[0x1301], &[]);
		let info_d = parse_client_hello(&with_sni);
		let info_i = parse_client_hello(&without_sni);
		assert_eq!(&info_d.ja4[3..4], "d", "SNI present should give 'd': {}", info_d.ja4);
		assert_eq!(&info_i.ja4[3..4], "i", "SNI absent should give 'i': {}", info_i.ja4);
	}

	#[test]
	fn test_ja4_sni_indicator_present_but_rejected_hostname() {
		// The indicator is keyed on extension PRESENCE per spec: an SNI whose value fails
		// symphony's hostname validation (here an IPv6 literal, contains ':') still gives 'd'
		// even though extract_sni returns None.
		let hello = make_client_hello(0x0303, &[0x1301], &[make_sni_ext(b"::1")]);
		let info = parse_client_hello(&hello);
		assert_eq!(info.sni, None, "invalid hostname should be rejected");
		assert_eq!(&info.ja4[3..4], "d", "SNI extension present should give 'd': {}", info.ja4);
	}

	#[test]
	fn test_ja4_cipher_count() {
		// 3 ciphers (including 1 GREASE) → cc=02.
		let hello = make_client_hello(
			0x0303,
			&[0x0A0A /* GREASE */, 0x1301, 0x1302],
			&[make_sni_ext(b"test")],
		);
		let info = parse_client_hello(&hello);
		assert_eq!(&info.ja4[4..6], "02", "cipher count should be 02 (GREASE excluded): {}", info.ja4);
	}

	#[test]
	fn test_ja4_extension_count_includes_sni_and_alpn() {
		// Spec: extension count includes SNI (0) and ALPN (16) even though they're excluded from the hash.
		// SNI + ALPN + supported_versions + sig_algs = 4 extensions counted.
		let hello = make_client_hello(
			0x0303,
			&[0x1301, 0x1302],
			&[
				make_sni_ext(b"test"),
				make_alpn_ext(&[b"h2"]),
				make_supported_versions_ext(&[0x0304]),
				make_sig_algs_ext(&[0x0403, 0x0807]),
			],
		);
		let info = parse_client_hello(&hello);
		assert_eq!(&info.ja4[6..8], "04", "extension count should be 04 (incl SNI+ALPN): {}", info.ja4);
	}

	#[test]
	fn test_ja4_alpn_chars() {
		// "h2" → first='h', last='2' → "h2"
		// "http/1.1" → first='h', last='1' → "h1"
		// no ALPN → "00"
		let with_h2 = make_client_hello(0x0303, &[0x1301], &[make_alpn_ext(&[b"h2"])]);
		let with_http11 = make_client_hello(0x0303, &[0x1301], &[make_alpn_ext(&[b"http/1.1"])]);
		let no_alpn = make_client_hello(0x0303, &[0x1301], &[]);

		let info_h2 = parse_client_hello(&with_h2);
		let info_http11 = parse_client_hello(&with_http11);
		let info_no = parse_client_hello(&no_alpn);

		assert_eq!(&info_h2.ja4[8..10], "h2", "h2 ALPN: {}", info_h2.ja4);
		assert_eq!(&info_http11.ja4[8..10], "h1", "http/1.1 ALPN: {}", info_http11.ja4);
		assert_eq!(&info_no.ja4[8..10], "00", "no ALPN: {}", info_no.ja4);
	}

	#[test]
	fn test_ja4_known_vector() {
		// Synthetic vector: verify Part A exactly and that Parts B/C are consistent
		// with the expected hash inputs.
		// Inputs:
		//   legacy_version = 0x0303 (TLS 1.2)
		//   supported_versions = [0x0304] → TLS 1.3 → "13"
		//   ciphers = [0x1301, 0x1302] → sorted → "1301,1302"
		//   extensions (non-GREASE, 4 total incl SNI+ALPN):
		//     SNI("test"), ALPN("h2"), supported_versions, sig_algs
		//     → for hash: sorted without SNI/ALPN → 000d,002b
		//     → sigalgs (unsorted) → 0403,0807
		//   hash input for Part C: "000d,002b_0403,0807"
		let hello = make_client_hello(
			0x0303,
			&[0x1301, 0x1302],
			&[
				make_sni_ext(b"test"),
				make_alpn_ext(&[b"h2"]),
				make_supported_versions_ext(&[0x0304]),
				make_sig_algs_ext(&[0x0403, 0x0807]),
			],
		);
		let info = parse_client_hello(&hello);

		assert!(info.ja4.starts_with("t13d0204h2_"), "Part A: {}", info.ja4);

		// Independently compute expected Part B and C using sha256_hex12.
		let expected_b = sha256_hex12(b"1301,1302");
		let expected_c = sha256_hex12(b"000d,002b_0403,0807");
		let expected = format!("t13d0204h2_{expected_b}_{expected_c}");
		assert_eq!(info.ja4, expected, "JA4 mismatch");
	}

	#[test]
	fn test_ja4_grease_excluded_from_ext_hash() {
		// Adding a GREASE extension should not change Part A counts or Part C hash.
		let without_grease = make_client_hello(
			0x0303,
			&[0x1301],
			&[make_supported_versions_ext(&[0x0303])],
		);
		let with_grease = make_client_hello(
			0x0303,
			&[0x1301],
			&[
				make_extension(0x2A2A, &[0x00]), // GREASE extension
				make_supported_versions_ext(&[0x0303]),
			],
		);
		let info_without = parse_client_hello(&without_grease);
		let info_with = parse_client_hello(&with_grease);
		// Both should have ext_count=01 (only supported_versions, no GREASE counted)
		assert_eq!(&info_without.ja4[6..8], "01", "without GREASE: {}", info_without.ja4);
		assert_eq!(&info_with.ja4[6..8], "01", "with GREASE: {}", info_with.ja4);
		// Part C should be identical
		let parts_without: Vec<&str> = info_without.ja4.split('_').collect();
		let parts_with: Vec<&str> = info_with.ja4.split('_').collect();
		assert_eq!(parts_without[2], parts_with[2], "GREASE ext should not affect Part C");
	}

	#[test]
	fn test_ja4_sni_excluded_from_ext_hash() {
		// Changing SNI value should not change Part C (SNI ext excluded from hash).
		let hello_a = make_client_hello(0x0303, &[0x1301], &[make_sni_ext(b"a.example.com")]);
		let hello_b = make_client_hello(0x0303, &[0x1301], &[make_sni_ext(b"b.example.com")]);
		let info_a = parse_client_hello(&hello_a);
		let info_b = parse_client_hello(&hello_b);
		let parts_a: Vec<&str> = info_a.ja4.split('_').collect();
		let parts_b: Vec<&str> = info_b.ja4.split('_').collect();
		assert_eq!(parts_a[2], parts_b[2], "Different SNI values should produce same Part C");
	}

	// ── SNI parsing (existing test) ──────────────────────────────────────────

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
		assert!(!info.ja4.is_empty());
		assert_eq!(info.ja4.len(), 36, "JA4 should be 36 chars (10+1+12+1+12): {}", info.ja4);
	}
}
