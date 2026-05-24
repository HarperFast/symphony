/// HTTP/1.1 header parsing and response rewriting utilities for the UDS proxy loop.
///
/// Harper's UDS sockets send `Connection: close` per response even for HTTP/1.1
/// clients.  The TLS-terminating proxy loop in proxy_conn.rs uses these helpers
/// to:
///   1. Frame individual request / response messages (find \r\n\r\n).
///   2. Rewrite `Connection: close` → `Connection: keep-alive` in upstream
///      responses so downstream TLS connections are reused.
///   3. Copy body bytes for Content-Length or read-until-close semantics.

use std::io;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const MAX_HEADER_SIZE: usize = 64 * 1024;

// ── Header framing ─────────────────────────────────────────────────────────────

/// Read from `reader` until the first `\r\n\r\n` (end of HTTP headers).
///
/// Returns `(header_block, excess)`:
/// - `header_block` includes the trailing `\r\n\r\n`.
/// - `excess` contains any bytes read beyond the header boundary.
/// - Both vecs are empty if EOF is reached before any data arrives.
pub async fn read_http_headers<R: AsyncRead + Unpin>(
	reader: &mut R,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
	let mut buf: Vec<u8> = Vec::with_capacity(2048);
	let mut tmp = [0u8; 4096];

	loop {
		if buf.len() > MAX_HEADER_SIZE {
			return Err(io::Error::new(
				io::ErrorKind::InvalidData,
				"HTTP headers exceed 64 KB limit",
			));
		}

		// Search only in the most-recently-appended region.
		let search_start = buf.len().saturating_sub(3 + tmp.len()); // overlap for boundary splits
		if let Some(rel) = buf[search_start..].windows(4).position(|w| w == b"\r\n\r\n") {
			let end = search_start + rel + 4;
			let excess = buf[end..].to_vec();
			buf.truncate(end);
			return Ok((buf, excess));
		}

		let n = reader.read(&mut tmp).await?;
		if n == 0 {
			return Ok((Vec::new(), Vec::new())); // EOF before headers complete
		}
		buf.extend_from_slice(&tmp[..n]);
	}
}

// ── Header field helpers ───────────────────────────────────────────────────────

/// Return the trimmed value of the first header whose name matches `name_lower`
/// (case-insensitive comparison; caller must pass lowercase).  Skips the
/// request/status line.
fn header_value<'a>(headers: &'a str, name_lower: &str) -> Option<&'a str> {
	for line in headers.split("\r\n").skip(1) {
		if let Some(colon) = line.find(':') {
			if line[..colon].trim().to_ascii_lowercase() == name_lower {
				return Some(line[colon + 1..].trim());
			}
		}
	}
	None
}

/// Parse the `Content-Length` header value.
pub fn content_length(headers: &[u8]) -> Option<u64> {
	let text = std::str::from_utf8(headers).ok()?;
	header_value(text, "content-length")?.parse().ok()
}

/// Return `true` if `Transfer-Encoding: chunked` is present.
pub fn is_transfer_encoding_chunked(headers: &[u8]) -> bool {
	let text = match std::str::from_utf8(headers) {
		Ok(t) => t,
		Err(_) => return false,
	};
	header_value(text, "transfer-encoding")
		.map(|v| v.to_ascii_lowercase().contains("chunked"))
		.unwrap_or(false)
}

/// Return `true` if the `Connection: close` header is present.
pub fn is_connection_close(headers: &[u8]) -> bool {
	let text = match std::str::from_utf8(headers) {
		Ok(t) => t,
		Err(_) => return false,
	};
	header_value(text, "connection")
		.map(|v| v.trim().eq_ignore_ascii_case("close"))
		.unwrap_or(false)
}

/// Return `true` if a protocol upgrade is requested (e.g. WebSocket).
pub fn is_upgrade(headers: &[u8]) -> bool {
	let text = match std::str::from_utf8(headers) {
		Ok(t) => t,
		Err(_) => return false,
	};
	header_value(text, "upgrade").is_some()
		&& header_value(text, "connection")
			.map(|v| v.to_ascii_lowercase().contains("upgrade"))
			.unwrap_or(false)
}

/// Parse the HTTP response status code (first line: `HTTP/1.x NNN ...`).
pub fn status_code(headers: &[u8]) -> u16 {
	std::str::from_utf8(headers)
		.ok()
		.and_then(|s| s.split_whitespace().nth(1))
		.and_then(|code| code.parse().ok())
		.unwrap_or(200)
}

/// Byte slice of the HTTP request method (first token before a space).
pub fn request_method(headers: &[u8]) -> &[u8] {
	let end = headers.iter().position(|&b| b == b' ').unwrap_or(0);
	&headers[..end]
}

/// Byte slice of the HTTP request target (the path between the first two spaces
/// of the request line). Returns an empty slice if malformed.
pub fn request_target(headers: &[u8]) -> &[u8] {
	let Some(first_sp) = headers.iter().position(|&b| b == b' ') else {
		return &[];
	};
	let rest = &headers[first_sp + 1..];
	let end = rest
		.iter()
		.position(|&b| b == b' ' || b == b'\r' || b == b'\n')
		.unwrap_or(rest.len());
	&rest[..end]
}

/// Return the trimmed value of the `Host` header (case-insensitive), or `None`
/// if absent or the headers aren't valid UTF-8.  Strips any `:port` suffix.
/// IPv6 literals such as `[::1]:80` are returned as `[::1]`.
///
/// Returns `None` if the value contains a CR, LF, or NUL byte — guarding
/// against response-splitting attacks when the result is interpolated into
/// a redirect `Location` header.
pub fn host_header(headers: &[u8]) -> Option<&str> {
	let text = std::str::from_utf8(headers).ok()?;
	let value = header_value(text, "host")?;
	if value.bytes().any(|b| matches!(b, b'\r' | b'\n' | 0)) {
		return None;
	}
	let host_only = if value.starts_with('[') {
		let close = value.find(']')?;
		&value[..=close]
	} else if let Some(colon) = value.find(':') {
		&value[..colon]
	} else {
		value
	};
	if host_only.is_empty() {
		return None;
	}
	Some(host_only)
}

/// Return `true` if the HTTP response should include a body.
/// (Per RFC 7230 §3.3: 1xx, 204, 304 and HEAD responses have no body.)
pub fn response_has_body(status: u16, req_method: &[u8]) -> bool {
	if status < 200 || status == 204 || status == 304 {
		return false;
	}
	!req_method.eq_ignore_ascii_case(b"HEAD")
}

// ── Response header rewriting ─────────────────────────────────────────────────

/// Return a copy of `headers` with the `Connection` field replaced by (or
/// inserted as) `Connection: close`.  Used when forwarding an ACME request to
/// the upstream so the response stream has a clean EOF and the proxy doesn't
/// turn into a keep-alive tunnel.
///
/// `headers` must include the trailing `\r\n\r\n`.
pub fn with_connection_close(headers: &[u8]) -> Vec<u8> {
	rewrite_connection_header(headers, b"Connection: close\r\n")
}

/// Return a copy of `headers` with the `Connection` field replaced by (or
/// inserted as) `Connection: keep-alive`.
///
/// `headers` must include the trailing `\r\n\r\n`.
pub fn with_connection_keep_alive(headers: &[u8]) -> Vec<u8> {
	rewrite_connection_header(headers, b"Connection: keep-alive\r\n")
}

/// Return a copy of `headers` with any `Content-Length` and `Transfer-Encoding`
/// fields removed.  Intended for ACME proxy requests which we treat as
/// body-less GETs — stripping these headers avoids deadlocking the upstream if
/// a client lies about a body and never sends it.
pub fn strip_body_framing(headers: &[u8]) -> Vec<u8> {
	let text = match std::str::from_utf8(headers) {
		Ok(t) => t,
		Err(_) => return headers.to_vec(),
	};

	let mut out = Vec::with_capacity(headers.len());

	for (i, line) in text.split("\r\n").enumerate() {
		if line.is_empty() {
			continue;
		}
		if i == 0 {
			out.extend_from_slice(line.as_bytes());
			out.extend_from_slice(b"\r\n");
			continue;
		}
		if let Some(colon) = line.find(':') {
			let name = line[..colon].trim().to_ascii_lowercase();
			if name == "content-length" || name == "transfer-encoding" {
				continue;
			}
		}
		out.extend_from_slice(line.as_bytes());
		out.extend_from_slice(b"\r\n");
	}
	out.extend_from_slice(b"\r\n");
	out
}

fn rewrite_connection_header(headers: &[u8], replacement: &[u8]) -> Vec<u8> {
	let text = match std::str::from_utf8(headers) {
		Ok(t) => t,
		Err(_) => return headers.to_vec(), // not valid UTF-8 — return as-is
	};

	let mut out = Vec::with_capacity(headers.len() + 32);
	let mut replaced = false;

	for (i, line) in text.split("\r\n").enumerate() {
		if line.is_empty() {
			continue; // skip the empty fragments produced by splitting on \r\n\r\n
		}
		if i == 0 {
			// Status / request line — pass through unchanged.
			out.extend_from_slice(line.as_bytes());
			out.extend_from_slice(b"\r\n");
		} else if let Some(colon) = line.find(':') {
			if line[..colon].trim().eq_ignore_ascii_case("connection") {
				out.extend_from_slice(replacement);
				replaced = true;
			} else {
				out.extend_from_slice(line.as_bytes());
				out.extend_from_slice(b"\r\n");
			}
		} else {
			out.extend_from_slice(line.as_bytes());
			out.extend_from_slice(b"\r\n");
		}
	}

	if !replaced {
		out.extend_from_slice(replacement);
	}
	out.extend_from_slice(b"\r\n"); // end-of-headers blank line
	out
}

/// Insert `X-Forwarded-For: <ip>` after the first request line.
pub fn insert_x_forwarded_for(headers: &[u8], peer_ip: std::net::IpAddr) -> Vec<u8> {
	let xff = format!("X-Forwarded-For: {}\r\n", peer_ip);
	// End of first line (method SP path SP version \r\n)
	let insert_at = headers
		.windows(2)
		.position(|w| w == b"\r\n")
		.map(|p| p + 2)
		.unwrap_or(0);
	let mut out = Vec::with_capacity(headers.len() + xff.len());
	out.extend_from_slice(&headers[..insert_at]);
	out.extend_from_slice(xff.as_bytes());
	out.extend_from_slice(&headers[insert_at..]);
	out
}

// ── Body copying ───────────────────────────────────────────────────────────────

/// Copy exactly `n` bytes from `reader` to `writer`.
pub async fn copy_exact<R, W>(reader: &mut R, writer: &mut W, n: u64) -> io::Result<()>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	let mut remaining = n;
	let mut buf = [0u8; 8192];
	while remaining > 0 {
		let chunk = (remaining.min(buf.len() as u64)) as usize;
		let read = reader.read(&mut buf[..chunk]).await?;
		if read == 0 {
			return Err(io::Error::new(
				io::ErrorKind::UnexpectedEof,
				"upstream closed mid-body",
			));
		}
		writer.write_all(&buf[..read]).await?;
		remaining -= read as u64;
	}
	Ok(())
}
