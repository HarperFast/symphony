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
/// Cap on a chunked-framing control line (`<hex>[;ext]CRLF`, or a trailer line). Generous for
/// chunk extensions while keeping a line that never terminates from growing the buffer forever.
const MAX_CHUNK_LINE: usize = 1024;

fn bad(msg: &str) -> io::Error {
	io::Error::new(io::ErrorKind::InvalidData, msg)
}

// ── Header framing ─────────────────────────────────────────────────────────────

/// Read from `reader` into `carry` until it holds a complete header block, returning the offset
/// just past that block's terminating `\r\n\r\n`.
///
/// `carry` may already hold bytes left over from an earlier message, and on return everything
/// past the returned offset is the body / the next request — so this composes across the requests
/// of a keep-alive connection. `Ok(None)` means a clean EOF with nothing buffered; an EOF part-way
/// through a header block is `UnexpectedEof`. The block is capped at `MAX_HEADER_SIZE`.
pub async fn read_header_block<R: AsyncRead + Unpin>(
	reader: &mut R,
	carry: &mut Vec<u8>,
) -> io::Result<Option<usize>> {
	let mut tmp = [0u8; 4096];
	// Bytes before this offset can't begin a match that a later read completes.
	let mut scanned = 0usize;

	loop {
		if let Some(rel) = carry[scanned..].windows(4).position(|w| w == b"\r\n\r\n") {
			return Ok(Some(scanned + rel + 4));
		}
		scanned = carry.len().saturating_sub(3);

		if carry.len() > MAX_HEADER_SIZE {
			return Err(bad("HTTP headers exceed 64 KB limit"));
		}

		let n = reader.read(&mut tmp).await?;
		if n == 0 {
			return if carry.is_empty() {
				Ok(None)
			} else {
				Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed mid-header"))
			};
		}
		carry.extend_from_slice(&tmp[..n]);
	}
}

/// Read from `reader` until the first `\r\n\r\n` (end of HTTP headers).
///
/// Returns `(header_block, excess)`:
/// - `header_block` includes the trailing `\r\n\r\n`.
/// - `excess` contains any bytes read beyond the header boundary.
/// - Both vecs are empty if EOF is reached before any data arrives.
pub async fn read_http_headers<R: AsyncRead + Unpin>(
	reader: &mut R,
) -> io::Result<(Vec<u8>, Vec<u8>)> {
	let mut carry: Vec<u8> = Vec::with_capacity(2048);
	match read_header_block(reader, &mut carry).await {
		Ok(Some(end)) => {
			let excess = carry[end..].to_vec();
			carry.truncate(end);
			Ok((carry, excess))
		}
		Ok(None) => Ok((Vec::new(), Vec::new())),
		// An EOF part-way through the headers stays a soft "nothing to serve" for this caller.
		Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok((Vec::new(), Vec::new())),
		Err(e) => Err(e),
	}
}

// ── Header field helpers ───────────────────────────────────────────────────────

/// Iterate the header fields of `block` as raw `(name, value)` byte slices,
/// skipping the request/status line and stopping at the blank line. Byte-oriented
/// so a header value carrying obs-text (0x80–0xFF, valid per RFC 7230 §3.2.6)
/// never poisons parsing of *other* fields the way whole-block UTF-8 validation did.
fn header_fields(block: &[u8]) -> impl Iterator<Item = (&[u8], &[u8])> {
	let body_start = block.len(); // fields never span past the block the caller framed
	let mut rest = match block.windows(2).position(|w| w == b"\r\n") {
		Some(p) => &block[p + 2..body_start],
		None => &[][..],
	};
	std::iter::from_fn(move || {
		loop {
			let line_end = rest.windows(2).position(|w| w == b"\r\n")?;
			let line = &rest[..line_end];
			rest = &rest[line_end + 2..];
			if line.is_empty() {
				return None; // end of headers
			}
			let Some(colon) = line.iter().position(|&b| b == b':') else {
				continue;
			};
			return Some((trim_ascii(&line[..colon]), trim_ascii(&line[colon + 1..])));
		}
	})
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
	let start = bytes.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(bytes.len());
	let end = bytes.iter().rposition(|b| !b.is_ascii_whitespace()).map_or(start, |p| p + 1);
	&bytes[start..end]
}

/// The trimmed value of the first header named `name` (case-insensitive).
fn header_field<'a>(block: &'a [u8], name: &str) -> Option<&'a [u8]> {
	header_fields(block)
		.find(|(n, _)| n.eq_ignore_ascii_case(name.as_bytes()))
		.map(|(_, v)| v)
}

/// Return `true` if any `Connection` header (there may be several, each a
/// comma-separated token list) contains `token`.
fn connection_has_token(block: &[u8], token: &str) -> bool {
	header_fields(block)
		.filter(|(n, _)| n.eq_ignore_ascii_case(b"connection"))
		.flat_map(|(_, v)| v.split(|&b| b == b','))
		.any(|t| trim_ascii(t).eq_ignore_ascii_case(token.as_bytes()))
}

/// Parse the `Content-Length` header value.
pub fn content_length(headers: &[u8]) -> Option<u64> {
	std::str::from_utf8(header_field(headers, "content-length")?)
		.ok()?
		.parse()
		.ok()
}

/// Return `true` if `Transfer-Encoding: chunked` is present.
pub fn is_transfer_encoding_chunked(headers: &[u8]) -> bool {
	header_field(headers, "transfer-encoding")
		.map(|v| {
			v.split(|&b| b == b',')
				.any(|t| trim_ascii(t).eq_ignore_ascii_case(b"chunked"))
		})
		.unwrap_or(false)
}

/// Return `true` if the `Connection: close` header is present.
pub fn is_connection_close(headers: &[u8]) -> bool {
	connection_has_token(headers, "close")
}

/// Return `true` if a protocol upgrade is requested (e.g. WebSocket).
/// `Connection` may be split across several fields (`Connection: keep-alive` +
/// `Connection: Upgrade`) — every field's token list counts.
pub fn is_upgrade(headers: &[u8]) -> bool {
	header_fields(headers).any(|(n, _)| n.eq_ignore_ascii_case(b"upgrade"))
		&& connection_has_token(headers, "upgrade")
}

/// Parse the HTTP response status code (first line: `HTTP/1.x NNN ...`).
pub fn status_code(headers: &[u8]) -> u16 {
	parse_status(headers).unwrap_or(200)
}

/// Status code of a response head, or `None` when the status line is malformed.
fn parse_status(headers: &[u8]) -> Option<u16> {
	let line_end = headers.windows(2).position(|w| w == b"\r\n")?;
	let mut fields = headers[..line_end].split(|&b| b == b' ').filter(|f| !f.is_empty());
	let code = fields.nth(1)?;
	std::str::from_utf8(code).ok()?.parse().ok()
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
/// if absent or the value isn't valid UTF-8.  Strips any `:port` suffix.
/// IPv6 literals such as `[::1]:80` are returned as `[::1]`.
///
/// Returns `None` if the value contains a CR, LF, or NUL byte — guarding
/// against response-splitting attacks when the result is interpolated into
/// a redirect `Location` header.
pub fn host_header(headers: &[u8]) -> Option<&str> {
	let value = std::str::from_utf8(header_field(headers, "host")?).ok()?;
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
				"closed mid-body",
			));
		}
		writer.write_all(&buf[..read]).await?;
		remaining -= read as u64;
	}
	Ok(())
}

// ── Request-stream rewriting (client → upstream) ───────────────────────────────

/// A header symphony owns end-to-end on the client→upstream path.
///
/// Any client-supplied copy is dropped, and `value` — when symphony has an authoritative one to
/// state — is inserted after the request line. A `None` value still strips: a client must never be
/// able to smuggle a value through on a request where symphony has nothing of its own to say.
pub struct HeaderRewrite {
	pub name: &'static str,
	pub value: Option<String>,
}

/// How the body of the request described by `block` is framed — i.e. where the *next* request on
/// this connection starts.
enum RequestBody {
	/// No body; the next request follows the header block immediately.
	None,
	Length(u64),
	Chunked,
}

/// Rewrite one request's header block: drop every client-supplied copy of a `rewrites` name, and
/// insert symphony's authoritative values right after the request line. `block` must be a complete
/// header block including the trailing `\r\n\r\n`.
///
/// Malformed framing is refused rather than forwarded — a header block we can't parse exactly is
/// one whose stripping we can't guarantee. Obs-fold continuations (RFC 7230 §3.2.4 deprecates
/// them) are rejected in particular because a fold following a stripped header would silently
/// re-attach the attacker's value to the preceding header.
fn rewrite_request_head(block: &[u8], rewrites: &[HeaderRewrite]) -> io::Result<Vec<u8>> {
	let Some(rl_end) = block.windows(2).position(|w| w == b"\r\n").map(|p| p + 2) else {
		return Err(bad("malformed HTTP request line"));
	};

	let mut out = Vec::with_capacity(block.len() + 128);
	out.extend_from_slice(&block[..rl_end]);
	for r in rewrites {
		if let Some(value) = &r.value {
			out.extend_from_slice(format!("{}: {}\r\n", r.name, value).as_bytes());
		}
	}

	let mut i = rl_end;
	while i < block.len() {
		let rel = block[i..]
			.windows(2)
			.position(|w| w == b"\r\n")
			.ok_or_else(|| bad("unterminated header line"))?;
		if rel == 0 {
			out.extend_from_slice(b"\r\n"); // end-of-headers blank line
			break;
		}
		let line = &block[i..i + rel];
		if matches!(line[0], b' ' | b'\t') {
			return Err(bad("obs-fold header continuation is not allowed"));
		}
		let colon = line
			.iter()
			.position(|&b| b == b':')
			.ok_or_else(|| bad("header line has no colon"))?;
		let name = &line[..colon];
		// `Foo : v` — whitespace before the colon is a classic smuggling primitive: peers
		// disagree on whether the name is `Foo` or `Foo `.
		if name.is_empty() || name.iter().any(|b| b.is_ascii_whitespace()) {
			return Err(bad("malformed header name"));
		}
		if !rewrites.iter().any(|r| r.name.as_bytes().eq_ignore_ascii_case(name)) {
			out.extend_from_slice(&block[i..i + rel + 2]);
		}
		i += rel + 2;
	}

	Ok(out)
}

/// Determine the body framing of the request in `block`. Byte-oriented: a header
/// value carrying obs-text (0x80–0xFF, valid per RFC 7230 §3.2.6) must not get the
/// request rejected — only the framing fields themselves need to parse.
fn request_body(block: &[u8]) -> io::Result<RequestBody> {
	let mut transfer_encoding = false;
	let mut chunked = false;
	let mut length: Option<u64> = None;

	for (name, value) in header_fields(block) {
		if name.eq_ignore_ascii_case(b"transfer-encoding") {
			transfer_encoding = true;
			// Only a *final* `chunked` leaves us frame boundaries we can follow.
			chunked = value
				.rsplit(|&b| b == b',')
				.next()
				.map(|last| trim_ascii(last).eq_ignore_ascii_case(b"chunked"))
				.unwrap_or(false);
		} else if name.eq_ignore_ascii_case(b"content-length") {
			let n: u64 = std::str::from_utf8(value)
				.ok()
				.and_then(|v| v.parse().ok())
				.ok_or_else(|| bad("malformed Content-Length"))?;
			if length.map(|prev| prev != n).unwrap_or(false) {
				return Err(bad("conflicting Content-Length headers"));
			}
			length = Some(n);
		}
	}

	if transfer_encoding {
		// TE+CL together is the classic request-smuggling primitive, and a non-chunked TE gives
		// us no boundary at all. Refuse instead of guessing where the next request begins.
		if length.is_some() {
			return Err(bad("both Transfer-Encoding and Content-Length present"));
		}
		if !chunked {
			return Err(bad("unsupported Transfer-Encoding"));
		}
		return Ok(RequestBody::Chunked);
	}

	Ok(match length {
		Some(0) | None => RequestBody::None,
		Some(n) => RequestBody::Length(n),
	})
}

/// Copy `n` body bytes through, draining anything already buffered in `carry` before reading more.
async fn copy_body<R, W>(reader: &mut R, writer: &mut W, carry: &mut Vec<u8>, n: u64) -> io::Result<()>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	let buffered = (carry.len() as u64).min(n) as usize;
	writer.write_all(&carry[..buffered]).await?;
	carry.drain(..buffered);
	let remaining = n - buffered as u64;
	if remaining > 0 {
		copy_exact(reader, writer, remaining).await?;
	}
	Ok(())
}

/// Read one CRLF-terminated control line, drawing from `carry` first. The returned line includes
/// its CRLF and is removed from `carry`; any bytes past it stay buffered.
async fn read_control_line<R: AsyncRead + Unpin>(
	reader: &mut R,
	carry: &mut Vec<u8>,
) -> io::Result<Vec<u8>> {
	let mut tmp = [0u8; 256];
	let mut scanned = 0usize;
	loop {
		if let Some(rel) = carry[scanned..].windows(2).position(|w| w == b"\r\n") {
			let end = scanned + rel + 2;
			let line = carry[..end].to_vec();
			carry.drain(..end);
			return Ok(line);
		}
		scanned = carry.len().saturating_sub(1);

		if carry.len() > MAX_CHUNK_LINE {
			return Err(bad("chunked framing line exceeds limit"));
		}
		let n = reader.read(&mut tmp).await?;
		if n == 0 {
			return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "closed mid-chunk"));
		}
		carry.extend_from_slice(&tmp[..n]);
	}
}

/// Stream a chunked body through verbatim, following its frame markers only so we know where the
/// next request begins. Chunk data and trailers are passed through untouched — backends surface
/// trailers separately from headers, so they aren't a header-spoofing surface.
async fn copy_chunked_body<R, W>(reader: &mut R, writer: &mut W, carry: &mut Vec<u8>) -> io::Result<()>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	loop {
		let line = read_control_line(reader, carry).await?;
		let size_field = line[..line.len() - 2].split(|&b| b == b';').next().unwrap_or(&[]);
		let size_text = std::str::from_utf8(size_field)
			.map_err(|_| bad("malformed chunk size"))?
			.trim();
		let size = u64::from_str_radix(size_text, 16).map_err(|_| bad("malformed chunk size"))?;
		writer.write_all(&line).await?;

		if size == 0 {
			// Trailer section: lines until a blank one closes the body.
			loop {
				let trailer = read_control_line(reader, carry).await?;
				writer.write_all(&trailer).await?;
				if trailer == b"\r\n" {
					return Ok(());
				}
			}
		}

		copy_body(reader, writer, carry, size).await?;
		let crlf = read_control_line(reader, carry).await?;
		if crlf != b"\r\n" {
			return Err(bad("missing CRLF after chunk data"));
		}
		writer.write_all(&crlf).await?;
	}
}

/// Per-request metadata the request pump hands the response pump so responses can be framed and
/// matched back to what asked for them.
struct RequestMeta {
	/// HEAD responses carry framing headers but no body.
	head_only: bool,
	/// CONNECT: a 2xx response establishes a tunnel.
	connect: bool,
	/// Upgrade request: a 101 response establishes a tunnel.
	upgrade: bool,
	/// Present on tunnel candidates: the response pump reports whether the upstream accepted.
	verdict: Option<tokio::sync::oneshot::Sender<bool>>,
}

/// Rewrite the header block of **every** HTTP/1 request on the client→upstream half of a
/// connection, applying `rewrites` to each.
///
/// Each request's header block is framed in full before it is rewritten (bounded at
/// `MAX_HEADER_SIZE`), so a client can't slip a spoofed header past the strip by fragmenting it
/// across TCP segments, pushing it beyond a fixed read size, or sending it on a later keep-alive
/// or pipelined request. Bodies are framed — not buffered — purely to locate the next request.
///
/// A CONNECT/Upgrade request does **not** switch this pump to raw passthrough by itself: the
/// switch is gated on the response pump reporting that the upstream actually accepted the tunnel
/// (101, or 2xx for CONNECT). Without that gate, a client could pipeline a spoofed-header request
/// behind an upgrade the upstream rejects-but-keeps-alive and have it forwarded verbatim.
async fn rewrite_request_stream<R, W>(
	reader: &mut R,
	writer: &mut W,
	rewrites: &[HeaderRewrite],
	meta_tx: &tokio::sync::mpsc::UnboundedSender<RequestMeta>,
) -> io::Result<()>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	let mut carry: Vec<u8> = Vec::with_capacity(2048);
	loop {
		let Some(end) = read_header_block(reader, &mut carry).await? else {
			return Ok(()); // clean EOF between requests
		};
		let head = rewrite_request_head(&carry[..end], rewrites)?;
		let is_connect = request_method(&carry[..end]).eq_ignore_ascii_case(b"CONNECT");
		let is_tunnel_candidate = is_connect || is_upgrade(&carry[..end]);
		// CONNECT has no body by definition; an Upgrade request still uses normal framing
		// until the upstream switches protocols.
		let body = if is_connect { RequestBody::None } else { request_body(&carry[..end])? };
		let head_only = request_method(&carry[..end]).eq_ignore_ascii_case(b"HEAD");

		let (verdict_tx, verdict_rx) = if is_tunnel_candidate {
			let (tx, rx) = tokio::sync::oneshot::channel();
			(Some(tx), Some(rx))
		} else {
			(None, None)
		};
		// Send meta before the head so the response pump's queue is in request order.
		if meta_tx
			.send(RequestMeta { head_only, connect: is_connect, upgrade: is_tunnel_candidate && !is_connect, verdict: verdict_tx })
			.is_err()
		{
			return Ok(()); // response pump is gone — the connection is closing
		}
		writer.write_all(&head).await?;
		carry.drain(..end);

		match body {
			RequestBody::None => {}
			RequestBody::Length(n) => copy_body(reader, writer, &mut carry, n).await?,
			RequestBody::Chunked => copy_chunked_body(reader, writer, &mut carry).await?,
		}

		if let Some(verdict_rx) = verdict_rx {
			match verdict_rx.await {
				Ok(true) => {
					// Tunnel established: the upgraded protocol isn't ours to parse.
					writer.write_all(&carry).await?;
					carry.clear();
					tokio::io::copy(reader, writer).await?;
					return Ok(());
				}
				// Upstream declined the tunnel and kept the connection: whatever the client
				// pipelined behind the upgrade is HTTP and stays under the rewriter.
				Ok(false) => {}
				Err(_) => return Ok(()), // response pump ended (upstream closed)
			}
		}
	}
}

/// How the body of the response described by a head block is framed.
enum ResponseBody {
	None,
	Length(u64),
	Chunked,
	/// No framing headers on a body-bearing response: the body runs to connection close.
	ReadToEnd,
}

fn response_body(head: &[u8], status: u16, head_only: bool) -> io::Result<ResponseBody> {
	if head_only || !response_has_body(status, if head_only { b"HEAD" } else { b"GET" }) {
		return Ok(ResponseBody::None);
	}
	if is_transfer_encoding_chunked(head) {
		return Ok(ResponseBody::Chunked);
	}
	match content_length(head) {
		Some(0) => Ok(ResponseBody::None),
		Some(n) => Ok(ResponseBody::Length(n)),
		None => Ok(ResponseBody::ReadToEnd),
	}
}

/// Forward upstream responses to the client, framing each one so tunnel verdicts can be
/// reported back to the request pump (see `rewrite_request_stream`).
async fn forward_response_stream<R, W>(
	reader: &mut R,
	writer: &mut W,
	meta_rx: &mut tokio::sync::mpsc::UnboundedReceiver<RequestMeta>,
) -> io::Result<()>
where
	R: AsyncRead + Unpin,
	W: AsyncWrite + Unpin,
{
	let mut carry: Vec<u8> = Vec::with_capacity(2048);
	loop {
		let Some(end) = read_header_block(reader, &mut carry).await? else {
			return Ok(()); // upstream closed between responses
		};
		let status = parse_status(&carry[..end]).ok_or_else(|| bad("malformed response status line"))?;

		// Interim responses (100 Continue etc.) precede the real one; 101 is the upgrade accept.
		if (100..200).contains(&status) && status != 101 {
			writer.write_all(&carry[..end]).await?;
			carry.drain(..end);
			continue;
		}

		let Some(mut meta) = meta_rx.recv().await else {
			// Response without a matching forwarded request: refuse to guess at framing.
			return Err(bad("upstream response with no corresponding request"));
		};

		let tunnel_established =
			(meta.upgrade && status == 101) || (meta.connect && (200..300).contains(&status));
		if let Some(verdict) = meta.verdict.take() {
			let _ = verdict.send(tunnel_established);
		} else if status == 101 {
			return Err(bad("unsolicited 101 response"));
		}

		let framing = response_body(&carry[..end], status, meta.head_only)?;
		writer.write_all(&carry[..end]).await?;
		carry.drain(..end);

		if tunnel_established {
			// Tunnel: the rest of the upstream stream is opaque; pass it through.
			writer.write_all(&carry).await?;
			carry.clear();
			tokio::io::copy(reader, writer).await?;
			return Ok(());
		}

		match framing {
			ResponseBody::None => {}
			ResponseBody::Length(n) => copy_body(reader, writer, &mut carry, n).await?,
			ResponseBody::Chunked => copy_chunked_body(reader, writer, &mut carry).await?,
			ResponseBody::ReadToEnd => {
				writer.write_all(&carry).await?;
				carry.clear();
				tokio::io::copy(reader, writer).await?;
				return Ok(());
			}
		}
	}
}

/// Bidirectional HTTP/1 proxying where the client→upstream half rewrites every request head and
/// tunnel switches (CONNECT / Upgrade) are gated on the upstream actually accepting them. The two
/// pumps run concurrently; each writer is shut down when its source reaches EOF (keep-alive
/// half-close), mirroring `copy_bidirectional`.
pub async fn proxy_http1_rewriting<C, U>(
	client: &mut C,
	upstream: &mut U,
	rewrites: &[HeaderRewrite],
) -> io::Result<()>
where
	C: AsyncRead + AsyncWrite + Unpin,
	U: AsyncRead + AsyncWrite + Unpin,
{
	let (mut client_read, mut client_write) = tokio::io::split(client);
	let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);
	let (meta_tx, mut meta_rx) = tokio::sync::mpsc::unbounded_channel();

	let client_to_upstream = async {
		let result = rewrite_request_stream(&mut client_read, &mut upstream_write, rewrites, &meta_tx).await;
		drop(meta_tx); // release the response pump's queue so it can finish
		let _ = upstream_write.shutdown().await;
		result
	};
	let upstream_to_client = async {
		let result = forward_response_stream(&mut upstream_read, &mut client_write, &mut meta_rx).await;
		let _ = client_write.shutdown().await;
		result
	};
	let (a, b) = tokio::join!(client_to_upstream, upstream_to_client);
	a.and(b)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::VecDeque;
	use std::pin::Pin;
	use std::task::{Context, Poll};

	const JA3: &str = "0123456789abcdef0123456789abcdef";

	/// A reader that yields its data in caller-defined chunks — one chunk per `poll_read` — so a
	/// test can reproduce TCP fragmentation exactly (a header split across two segments, etc.).
	struct ChunkReader {
		chunks: VecDeque<Vec<u8>>,
	}

	impl ChunkReader {
		fn new(chunks: &[&[u8]]) -> Self {
			Self { chunks: chunks.iter().map(|c| c.to_vec()).collect() }
		}
	}

	impl AsyncRead for ChunkReader {
		fn poll_read(
			mut self: Pin<&mut Self>,
			_cx: &mut Context<'_>,
			buf: &mut tokio::io::ReadBuf<'_>,
		) -> Poll<io::Result<()>> {
			if let Some(front) = self.chunks.front_mut() {
				let n = front.len().min(buf.remaining());
				buf.put_slice(&front[..n]);
				front.drain(..n);
				if front.is_empty() {
					self.chunks.pop_front();
				}
			}
			Poll::Ready(Ok(()))
		}
	}

	fn ja3_rewrite(value: Option<&str>) -> Vec<HeaderRewrite> {
		vec![HeaderRewrite { name: "X-JA3", value: value.map(str::to_string) }]
	}

	async fn run(chunks: &[&[u8]], rewrites: &[HeaderRewrite]) -> io::Result<String> {
		let mut reader = ChunkReader::new(chunks);
		let mut out: Vec<u8> = Vec::new();
		// Keep the receiver alive so meta sends succeed; none of these requests are
		// tunnel candidates, so no verdict is awaited.
		let (meta_tx, _meta_rx) = tokio::sync::mpsc::unbounded_channel();
		rewrite_request_stream(&mut reader, &mut out, rewrites, &meta_tx).await?;
		Ok(String::from_utf8(out).unwrap())
	}

	/// Drive the full request/response pump pair over in-memory duplex pipes: the test
	/// scripts the client's bytes and the upstream's responses, and gets back what each
	/// side received.
	async fn run_pair(client_sends: &[u8], upstream_sends: &[u8], rewrites: &[HeaderRewrite]) -> (String, String) {
		let (mut client_side, mut proxy_client_side) = tokio::io::duplex(64 * 1024);
		let (mut proxy_upstream_side, mut upstream_side) = tokio::io::duplex(64 * 1024);

		let proxy = proxy_http1_rewriting(&mut proxy_client_side, &mut proxy_upstream_side, rewrites);

		let client_data = client_sends.to_vec();
		let client = async move {
			client_side.write_all(&client_data).await.unwrap();
			client_side.shutdown().await.unwrap();
			let mut received = Vec::new();
			let _ = client_side.read_to_end(&mut received).await;
			received
		};
		let upstream_data = upstream_sends.to_vec();
		let upstream = async move {
			let mut received = Vec::new();
			// Read everything the proxy forwards, then answer with the scripted responses.
			// (Write first for tunnel bytes to flow; ordering is fine over duplex buffers.)
			upstream_side.write_all(&upstream_data).await.unwrap();
			upstream_side.shutdown().await.unwrap();
			let _ = upstream_side.read_to_end(&mut received).await;
			received
		};

		let (_, client_received, upstream_received) = tokio::join!(proxy, client, upstream);
		(
			String::from_utf8_lossy(&upstream_received).into_owned(),
			String::from_utf8_lossy(&client_received).into_owned(),
		)
	}

	#[tokio::test]
	async fn injects_after_request_line() {
		let got = run(
			&[b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"],
			&ja3_rewrite(Some(JA3)),
		)
		.await
		.unwrap();
		assert_eq!(got, format!("GET / HTTP/1.1\r\nX-JA3: {JA3}\r\nHost: x\r\n\r\n"));
	}

	#[tokio::test]
	async fn strips_client_supplied_copy_case_insensitive() {
		let got = run(
			&[b"POST /p HTTP/1.1\r\nx-ja3: deadbeef\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi"],
			&ja3_rewrite(Some(JA3)),
		)
		.await
		.unwrap();
		assert_eq!(
			got,
			format!("POST /p HTTP/1.1\r\nX-JA3: {JA3}\r\nHost: x\r\nContent-Length: 2\r\n\r\nhi")
		);
		assert!(!got.contains("deadbeef"));
	}

	// Finding 2 (a): a spoofed header split across two TCP segments must still be stripped.
	#[tokio::test]
	async fn strips_header_fragmented_across_reads() {
		let got = run(
			&[b"GET / HTTP/1.1\r\nX-JA", b"3: deadbeef\r\nHost: x\r\n\r", b"\n"],
			&ja3_rewrite(Some(JA3)),
		)
		.await
		.unwrap();
		assert_eq!(got, format!("GET / HTTP/1.1\r\nX-JA3: {JA3}\r\nHost: x\r\n\r\n"));
		assert!(!got.contains("deadbeef"));
	}

	// Finding 2 (c): a second keep-alive request must be rewritten too, not passed through raw.
	#[tokio::test]
	async fn rewrites_every_keep_alive_request() {
		let got = run(
			&[
				b"GET /1 HTTP/1.1\r\nHost: x\r\n\r\n",
				b"GET /2 HTTP/1.1\r\nX-JA3: spoofed\r\nHost: x\r\n\r\n",
			],
			&ja3_rewrite(Some(JA3)),
		)
		.await
		.unwrap();
		assert_eq!(
			got,
			format!(
				"GET /1 HTTP/1.1\r\nX-JA3: {JA3}\r\nHost: x\r\n\r\n\
				 GET /2 HTTP/1.1\r\nX-JA3: {JA3}\r\nHost: x\r\n\r\n"
			)
		);
		assert!(!got.contains("spoofed"));
	}

	// A body between two pipelined requests must pass through verbatim, and the request after it
	// must still be rewritten (proves body framing locates the next request correctly).
	#[tokio::test]
	async fn frames_content_length_body_then_rewrites_next() {
		let got = run(
			&[
				b"POST /1 HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello",
				b"GET /2 HTTP/1.1\r\nX-JA3: spoofed\r\n\r\n",
			],
			&ja3_rewrite(Some(JA3)),
		)
		.await
		.unwrap();
		assert_eq!(
			got,
			format!(
				"POST /1 HTTP/1.1\r\nX-JA3: {JA3}\r\nContent-Length: 5\r\n\r\nhello\
				 GET /2 HTTP/1.1\r\nX-JA3: {JA3}\r\n\r\n"
			)
		);
		assert!(!got.contains("spoofed"));
	}

	#[tokio::test]
	async fn frames_chunked_body_then_rewrites_next() {
		let got = run(
			&[
				b"POST /1 HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
				b"GET /2 HTTP/1.1\r\nX-JA3: spoofed\r\n\r\n",
			],
			&ja3_rewrite(Some(JA3)),
		)
		.await
		.unwrap();
		assert_eq!(
			got,
			format!(
				"POST /1 HTTP/1.1\r\nX-JA3: {JA3}\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n\
				 GET /2 HTTP/1.1\r\nX-JA3: {JA3}\r\n\r\n"
			)
		);
		assert!(!got.contains("spoofed"));
	}

	// Finding 2 (Medium): with no authoritative value the client copy is still stripped, and no
	// bogus replacement is injected.
	#[tokio::test]
	async fn strips_even_when_no_replacement_value() {
		let got = run(
			&[b"GET / HTTP/1.1\r\nX-JA3: spoofed\r\nHost: x\r\n\r\n"],
			&ja3_rewrite(None),
		)
		.await
		.unwrap();
		assert_eq!(got, "GET / HTTP/1.1\r\nHost: x\r\n\r\n");
		assert!(!got.contains("spoofed"));
		assert!(!got.contains("X-JA3"));
	}

	// Finding 2 (Slowloris-adjacent bound): a header block past the 64 KB cap is refused, not
	// buffered unbounded.
	#[tokio::test]
	async fn oversized_header_block_is_rejected() {
		let mut req = b"GET / HTTP/1.1\r\n".to_vec();
		req.extend_from_slice(b"X-Pad: ");
		req.resize(req.len() + 70 * 1024, b'A');
		req.extend_from_slice(b"\r\n\r\n");
		let mut reader = ChunkReader::new(&[&req]);
		let mut out: Vec<u8> = Vec::new();
		let (meta_tx, _meta_rx) = tokio::sync::mpsc::unbounded_channel();
		let err = rewrite_request_stream(&mut reader, &mut out, &ja3_rewrite(Some(JA3)), &meta_tx)
			.await
			.unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::InvalidData);
	}

	// Finding 2 (partial-first-read corruption): a request line arriving before its terminator
	// must not have headers prepended before it — the whole block is framed first.
	#[tokio::test]
	async fn partial_request_line_is_not_corrupted() {
		let got = run(
			&[b"GET /longpath HT", b"TP/1.1\r\nHost: x\r\n\r\n"],
			&ja3_rewrite(Some(JA3)),
		)
		.await
		.unwrap();
		assert!(got.starts_with("GET /longpath HTTP/1.1\r\n"), "request line intact: {got:?}");
		assert_eq!(got, format!("GET /longpath HTTP/1.1\r\nX-JA3: {JA3}\r\nHost: x\r\n\r\n"));
	}

	// An empty stream (client connects, sends nothing, closes) is a clean no-op — no spurious head.
	#[tokio::test]
	async fn empty_stream_is_clean() {
		let got = run(&[b""], &ja3_rewrite(Some(JA3))).await.unwrap();
		assert_eq!(got, "");
	}

	// Request-smuggling primitives are refused rather than forwarded ambiguously.
	#[tokio::test]
	async fn rejects_te_and_cl_together() {
		let err = run(
			&[b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n0\r\n\r\n"],
			&ja3_rewrite(Some(JA3)),
		)
		.await
		.unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::InvalidData);
	}

	#[tokio::test]
	async fn rejects_obs_fold_continuation() {
		let err = run(
			&[b"GET / HTTP/1.1\r\nX-JA3: a\r\n\tcontinued\r\nHost: x\r\n\r\n"],
			&ja3_rewrite(Some(JA3)),
		)
		.await
		.unwrap_err();
		assert_eq!(err.kind(), io::ErrorKind::InvalidData);
	}

	#[tokio::test]
	async fn no_rewrites_leaves_stream_verbatim() {
		let got = run(&[b"GET / HTTP/1.1\r\nX-JA3: keep\r\n\r\n"], &[]).await.unwrap();
		assert_eq!(got, "GET / HTTP/1.1\r\nX-JA3: keep\r\n\r\n");
	}

	// Obs-text (0x80–0xFF) in an unrelated header value is valid per RFC 7230 §3.2.6 and
	// must not get the request rejected — only the framing fields need to parse.
	#[tokio::test]
	async fn forwards_obs_text_header_values() {
		let req: &[u8] = b"GET / HTTP/1.1\r\nX-Custom: caf\xE9\r\nHost: x\r\n\r\n";
		let mut reader = ChunkReader::new(&[req]);
		let mut out: Vec<u8> = Vec::new();
		let (meta_tx, _meta_rx) = tokio::sync::mpsc::unbounded_channel();
		rewrite_request_stream(&mut reader, &mut out, &ja3_rewrite(Some(JA3)), &meta_tx)
			.await
			.unwrap();
		assert!(out.windows(4).any(|w| w == b"caf\xE9"), "obs-text header forwarded intact");
		assert!(String::from_utf8_lossy(&out).contains(&format!("X-JA3: {JA3}")));
	}

	// Multi-field Connection (`Connection: keep-alive` + `Connection: Upgrade`) is a valid
	// upgrade request and must be classified as a tunnel candidate.
	#[test]
	fn upgrade_across_multiple_connection_fields() {
		let head = b"GET /ws HTTP/1.1\r\nConnection: keep-alive\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
		assert!(is_upgrade(head));
		let head_tokens = b"GET /ws HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: websocket\r\n\r\n";
		assert!(is_upgrade(head_tokens));
		let no_upgrade = b"GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n";
		assert!(!is_upgrade(no_upgrade));
	}

	// ── Tunnel verdict gating (pump pair) ─────────────────────────────────────

	const UPGRADE_REQ: &[u8] =
		b"GET /ws HTTP/1.1\r\nHost: x\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nX-JA3: spoofed\r\n\r\n";

	// Upstream accepts the upgrade: everything after the 101 flows raw, both directions.
	#[tokio::test]
	async fn tunnel_after_accepted_upgrade() {
		let client_sends = [UPGRADE_REQ, b"\x88\x00raw-client-frames"].concat();
		let upstream_sends: &[u8] =
			b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n\x82\x01raw-upstream-frames";
		let (upstream_got, client_got) = run_pair(&client_sends, upstream_sends, &ja3_rewrite(Some(JA3))).await;
		assert!(upstream_got.contains(&format!("X-JA3: {JA3}")), "upgrade head rewritten");
		assert!(!upstream_got.contains("spoofed"));
		assert!(upstream_got.contains("raw-client-frames"), "client tunnel bytes flow");
		assert!(client_got.contains("101 Switching Protocols"));
		assert!(client_got.contains("raw-upstream-frames"), "upstream tunnel bytes flow");
	}

	// The heskew scenario: upstream REJECTS the upgrade but keeps the connection alive. A
	// request the client pipelined behind the upgrade must still be rewritten — not passed
	// through raw.
	#[tokio::test]
	async fn rejected_upgrade_keeps_rewriting_pipelined_requests() {
		let client_sends = [
			UPGRADE_REQ,
			b"GET /2 HTTP/1.1\r\nHost: x\r\nX-JA3: smuggled\r\n\r\n" as &[u8],
		]
		.concat();
		let upstream_sends: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n\
			HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
		let (upstream_got, client_got) = run_pair(&client_sends, upstream_sends, &ja3_rewrite(Some(JA3))).await;
		assert!(!upstream_got.contains("spoofed"), "upgrade head still stripped");
		assert!(!upstream_got.contains("smuggled"), "pipelined request must not bypass the rewriter");
		let occurrences = upstream_got.matches(&format!("X-JA3: {JA3}")).count();
		assert_eq!(occurrences, 2, "both requests carry the authoritative header");
		assert!(client_got.contains("400 Bad Request"));
		assert!(client_got.contains("ok"));
	}

	// CONNECT accepted (2xx) tunnels; CONNECT rejected keeps framing.
	#[tokio::test]
	async fn connect_verdicts() {
		let accepted = run_pair(
			&[b"CONNECT db:5432 HTTP/1.1\r\nHost: db\r\n\r\n" as &[u8], b"opaque-bytes"].concat(),
			b"HTTP/1.1 200 Connection Established\r\n\r\ntunnel-back",
			&ja3_rewrite(Some(JA3)),
		)
		.await;
		assert!(accepted.0.contains("opaque-bytes"), "client bytes tunnel after 2xx");
		assert!(accepted.1.contains("tunnel-back"));

		let rejected = run_pair(
			&[
				b"CONNECT db:5432 HTTP/1.1\r\nHost: db\r\n\r\n" as &[u8],
				b"GET /next HTTP/1.1\r\nX-JA3: smuggled\r\n\r\n",
			]
			.concat(),
			b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
			&ja3_rewrite(Some(JA3)),
		)
		.await;
		assert!(!rejected.0.contains("smuggled"), "post-CONNECT request stays under the rewriter");
	}

	// An interim 100 Continue is forwarded without consuming the request's response slot.
	#[tokio::test]
	async fn interim_response_then_final() {
		let (upstream_got, client_got) = run_pair(
			b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\nhi",
			b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndone",
			&ja3_rewrite(Some(JA3)),
		)
		.await;
		assert!(upstream_got.contains("hi"));
		assert!(client_got.contains("100 Continue"));
		assert!(client_got.contains("done"));
	}

	// HEAD responses carry framing headers but no body: the next response must still frame.
	#[tokio::test]
	async fn head_response_body_is_not_consumed() {
		let (_, client_got) = run_pair(
			b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\nGET /2 HTTP/1.1\r\nHost: x\r\n\r\n",
			b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nyes",
			&ja3_rewrite(Some(JA3)),
		)
		.await;
		assert!(client_got.contains("Content-Length: 100"));
		assert!(client_got.contains("yes"));
	}
}
