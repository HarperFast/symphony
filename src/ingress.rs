//! The receiving end of peer failover: a TLS listener that admits only `trustedSources`, requires a
//! PROXY v2 header, and takes the client address from it. A PROXY v2 LOCAL header carrying route
//! names is a peer's load query instead, answered with this node's load for each and closed.

use crate::metrics::BlockKind;
use crate::router::SourceAllowlist;
use arc_swap::ArcSwap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt};

const SIGNATURE: [u8; 12] = [
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];
/// Largest address block + TLV section accepted. A symphony peer sends no TLVs, so anything near
/// this is not a peer.
const MAX_PAYLOAD: usize = 512;
/// A load query names one route per TLV of this type (symphony's private range: 0xE0 JA3, 0xE1 JA4,
/// 0xE2 client certificate).
pub const LOAD_QUERY_TLV: u8 = 0xE3;
const MAX_QUERY_NAMES: usize = 64;
const MAX_NAME_LEN: usize = 253;
/// 64 TLVs of a 253-byte name and its 3-byte TLV header.
const MAX_LOCAL_PAYLOAD: usize = MAX_QUERY_NAMES * (3 + MAX_NAME_LEN);
const LOAD_ANSWER_MAGIC: &[u8] = b"SYMPHONY-LOAD/1\n";

pub struct IngressState {
	trusted: ArcSwap<SourceAllowlist>,
}

impl IngressState {
	pub fn new(trusted: SourceAllowlist) -> Arc<Self> {
		Arc::new(Self {
			trusted: ArcSwap::from_pointee(trusted),
		})
	}

	pub fn trusts(&self, peer: IpAddr) -> bool {
		self.trusted.load().permits(peer)
	}

	pub fn set_trusted(&self, trusted: SourceAllowlist) {
		self.trusted.store(Arc::new(trusted));
	}
}

#[derive(Debug, PartialEq, Eq)]
pub enum Header {
	/// A forwarded client connection, from this source address.
	Proxy(SocketAddr),
	/// A peer's load query: one entry per name asked about, `None` for a name that is not a valid
	/// DNS name (answered as not available).
	LoadQuery(Vec<Option<String>>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderReject {
	Invalid,
	Local,
	V1,
	Timeout,
}

impl From<HeaderReject> for BlockKind {
	fn from(r: HeaderReject) -> Self {
		match r {
			HeaderReject::Invalid => Self::ProxyHeaderInvalid,
			HeaderReject::Local => Self::ProxyHeaderLocal,
			HeaderReject::V1 => Self::ProxyHeaderV1,
			HeaderReject::Timeout => Self::ProxyHeaderTimeout,
		}
	}
}

/// Read exactly one PROXY v2 header. Reads, rather than peeks, so the ClientHello peek that follows
/// starts on the first byte after it. A PROXY command's TLVs are read past and ignored: the peer
/// terminates TLS itself and needs no TLS facts from the forwarding node.
pub async fn read_proxy_v2<S: AsyncRead + Unpin>(
	stream: &mut S,
	limit: Duration,
) -> Result<Header, HeaderReject> {
	let read = async {
		let mut fixed = [0u8; 16];
		stream
			.read_exact(&mut fixed)
			.await
			.map_err(|_| HeaderReject::Invalid)?;
		let len = match parse_fixed(&fixed)? {
			Command::Proxy(len) => len,
			Command::Local(len) => {
				let mut payload = vec![0u8; len];
				stream
					.read_exact(&mut payload)
					.await
					.map_err(|_| HeaderReject::Invalid)?;
				return parse_load_query(fixed[13], &payload).map(Header::LoadQuery);
			}
		};
		let addr_len = if fixed[13] == 0x11 { 12 } else { 36 };
		let mut addresses = [0u8; 36];
		stream
			.read_exact(&mut addresses[..addr_len])
			.await
			.map_err(|_| HeaderReject::Invalid)?;
		let mut tlvs = len - addr_len;
		let mut discard = [0u8; 64];
		while tlvs > 0 {
			let chunk = tlvs.min(discard.len());
			stream
				.read_exact(&mut discard[..chunk])
				.await
				.map_err(|_| HeaderReject::Invalid)?;
			tlvs -= chunk;
		}
		parse_source(fixed[13], &addresses[..addr_len]).map(Header::Proxy)
	};
	tokio::time::timeout(limit, read)
		.await
		.unwrap_or(Err(HeaderReject::Timeout))
}

enum Command {
	/// Payload length.
	Proxy(usize),
	Local(usize),
}

fn parse_fixed(fixed: &[u8; 16]) -> Result<Command, HeaderReject> {
	if fixed.starts_with(b"PROXY ") {
		return Err(HeaderReject::V1);
	}
	if fixed[..12] != SIGNATURE || fixed[12] >> 4 != 2 {
		return Err(HeaderReject::Invalid);
	}
	let len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
	match fixed[12] & 0x0F {
		0x1 => {}
		0x0 => {
			return match address_len(fixed[13]) {
				Some(addr_len) if (addr_len..=MAX_LOCAL_PAYLOAD).contains(&len) => {
					Ok(Command::Local(len))
				}
				_ => Err(HeaderReject::Invalid),
			};
		}
		_ => return Err(HeaderReject::Invalid),
	}
	let min = match fixed[13] {
		0x11 => 12, // TCP over IPv4
		0x21 => 36, // TCP over IPv6
		_ => return Err(HeaderReject::Invalid),
	};
	if len < min || len > MAX_PAYLOAD {
		return Err(HeaderReject::Invalid);
	}
	Ok(Command::Proxy(len))
}

/// The address block's length for a family a LOCAL header may carry (it carries no client).
fn address_len(family: u8) -> Option<usize> {
	match family {
		0x00 => Some(0),
		0x11 => Some(12),
		0x21 => Some(36),
		_ => None,
	}
}

/// The route names of a LOCAL header's `LOAD_QUERY_TLV`s, in order. No names is a plain LOCAL
/// (a health check), rejected as before.
fn parse_load_query(family: u8, payload: &[u8]) -> Result<Vec<Option<String>>, HeaderReject> {
	let mut tlvs = &payload[address_len(family).ok_or(HeaderReject::Invalid)?..];
	let mut names = Vec::new();
	while !tlvs.is_empty() {
		let [kind, hi, lo, rest @ ..] = tlvs else {
			return Err(HeaderReject::Invalid);
		};
		let len = u16::from_be_bytes([*hi, *lo]) as usize;
		let value = rest.get(..len).ok_or(HeaderReject::Invalid)?;
		tlvs = &rest[len..];
		if *kind == LOAD_QUERY_TLV {
			if names.len() == MAX_QUERY_NAMES {
				return Err(HeaderReject::Invalid);
			}
			names.push(valid_name(value).map(str::to_owned));
		}
	}
	if names.is_empty() {
		return Err(HeaderReject::Local);
	}
	Ok(names)
}

/// A route name as a load query may ask about: an exact DNS name, ASCII letters, digits, `-` and `.`.
fn valid_name(value: &[u8]) -> Option<&str> {
	let valid = (1..=MAX_NAME_LEN).contains(&value.len())
		&& value
			.iter()
			.all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'.');
	valid.then(|| std::str::from_utf8(value).ok()).flatten()
}

/// Route names grouped into queries that each fit the receiver's bounds. A name the receiver would
/// not accept is still sent and answered as not available, so answers stay aligned with names.
pub fn load_query_chunks<T: AsRef<str>>(names: &[T]) -> impl Iterator<Item = &[T]> {
	names.chunks(MAX_QUERY_NAMES)
}

/// A PROXY v2 LOCAL header, family UNSPEC, with one `LOAD_QUERY_TLV` per name. A name longer than
/// a DNS name is sent empty, which the receiver answers as not available.
pub fn encode_load_query<T: AsRef<str>>(names: &[T]) -> Vec<u8> {
	let mut tlvs = Vec::new();
	for name in names {
		let name = name.as_ref().as_bytes();
		let name = if name.len() <= MAX_NAME_LEN {
			name
		} else {
			&[]
		};
		tlvs.push(LOAD_QUERY_TLV);
		tlvs.extend_from_slice(&(name.len() as u16).to_be_bytes());
		tlvs.extend_from_slice(name);
	}
	let mut out = Vec::with_capacity(16 + tlvs.len());
	out.extend_from_slice(&SIGNATURE);
	out.push(0x20);
	out.push(0x00);
	out.extend_from_slice(&(tlvs.len() as u16).to_be_bytes());
	out.extend_from_slice(&tlvs);
	out
}

/// The answer to a load query: one line per name, its load in permille or `-` when this node would
/// not take a spilled connection for it.
pub fn encode_load_answer(loads: &[Option<u32>]) -> Vec<u8> {
	let mut out = LOAD_ANSWER_MAGIC.to_vec();
	for load in loads {
		match load {
			Some(permille) => {
				out.extend_from_slice(format!("{}\n", permille.min(&1000)).as_bytes())
			}
			None => out.extend_from_slice(b"-\n"),
		}
	}
	out
}

pub fn max_load_answer_len(names: usize) -> usize {
	LOAD_ANSWER_MAGIC.len() + names * "1000\n".len()
}

/// `None` unless `answer` is exactly a well-formed answer for `expected` names.
pub fn parse_load_answer(answer: &[u8], expected: usize) -> Option<Vec<Option<u32>>> {
	if answer.len() > max_load_answer_len(expected) {
		return None;
	}
	let body = std::str::from_utf8(answer.strip_prefix(LOAD_ANSWER_MAGIC)?).ok()?;
	let body = body.strip_suffix('\n').unwrap_or(body);
	let lines: Vec<&str> = if body.is_empty() {
		Vec::new()
	} else {
		body.split('\n').collect()
	};
	if lines.len() != expected || !answer.ends_with(b"\n") {
		return None;
	}
	lines
		.into_iter()
		.map(|line| match line {
			"-" => Some(None),
			digits
				if (1..=4).contains(&digits.len())
					&& digits.bytes().all(|b| b.is_ascii_digit()) =>
			{
				digits.parse::<u32>().ok().filter(|v| *v <= 1000).map(Some)
			}
			_ => None,
		})
		.collect()
}

fn parse_source(family: u8, payload: &[u8]) -> Result<SocketAddr, HeaderReject> {
	let (ip, port_at) = match family {
		0x11 => {
			let octets: [u8; 4] = payload[0..4]
				.try_into()
				.map_err(|_| HeaderReject::Invalid)?;
			(IpAddr::V4(Ipv4Addr::from(octets)), 8)
		}
		0x21 => {
			let octets: [u8; 16] = payload[0..16]
				.try_into()
				.map_err(|_| HeaderReject::Invalid)?;
			(IpAddr::V6(Ipv6Addr::from(octets)).to_canonical(), 32)
		}
		_ => return Err(HeaderReject::Invalid),
	};
	let port = u16::from_be_bytes([payload[port_at], payload[port_at + 1]]);
	Ok(SocketAddr::new(ip, port))
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::upstream::write_proxy_v2_header;

	async fn header(src: &str, dst: &str, tlvs: &[(u8, &[u8])]) -> Vec<u8> {
		let mut out = Vec::new();
		write_proxy_v2_header(
			&mut out,
			src.parse().unwrap(),
			Some(dst.parse().unwrap()),
			tlvs,
		)
		.await
		.unwrap();
		out
	}

	async fn read_header(bytes: &[u8]) -> Result<Header, HeaderReject> {
		let mut input = bytes;
		read_proxy_v2(&mut input, Duration::from_secs(1)).await
	}

	async fn read(bytes: &[u8]) -> Result<SocketAddr, HeaderReject> {
		match read_header(bytes).await? {
			Header::Proxy(source) => Ok(source),
			other => panic!("expected a PROXY header, got {other:?}"),
		}
	}

	#[tokio::test]
	async fn reads_ipv4_and_leaves_the_following_bytes() {
		let mut bytes = header("203.0.113.7:5000", "10.0.0.1:9443", &[]).await;
		bytes.extend_from_slice(b"\x16\x03\x01rest");
		let mut input = &bytes[..];
		let src = read_proxy_v2(&mut input, Duration::from_secs(1))
			.await
			.unwrap();
		assert_eq!(src, Header::Proxy("203.0.113.7:5000".parse().unwrap()));
		assert_eq!(input, b"\x16\x03\x01rest", "only the header is consumed");
	}

	#[tokio::test]
	async fn reads_ipv6_and_ignores_tlvs() {
		let bytes = header(
			"[2001:db8::7]:443",
			"[2001:db8::1]:9443",
			&[(0xE0, b"forged-ja3"), (0x20, b"\x01\0\0\0\0")],
		)
		.await;
		assert_eq!(
			read(&bytes).await.unwrap(),
			"[2001:db8::7]:443".parse().unwrap()
		);
	}

	#[tokio::test]
	async fn tlvs_longer_than_the_discard_buffer_are_consumed_exactly() {
		let tlv = vec![0x5A; 200];
		let mut bytes = header("203.0.113.7:5000", "10.0.0.1:9443", &[(0xE0, &tlv)]).await;
		bytes.extend_from_slice(b"\x16next");
		let mut input = &bytes[..];
		let src = read_proxy_v2(&mut input, Duration::from_secs(1))
			.await
			.unwrap();
		assert_eq!(src, Header::Proxy("203.0.113.7:5000".parse().unwrap()));
		assert_eq!(input, b"\x16next");
	}

	#[tokio::test]
	async fn a_mapped_ipv6_source_becomes_ipv4() {
		let mut bytes = header("[2001:db8::7]:443", "[2001:db8::1]:9443", &[]).await;
		bytes[16..32].copy_from_slice(&"::ffff:198.51.100.4".parse::<Ipv6Addr>().unwrap().octets());
		assert_eq!(
			read(&bytes).await.unwrap(),
			"198.51.100.4:443".parse().unwrap()
		);
	}

	#[tokio::test]
	async fn rejects_local_v1_malformed_truncated_oversized_and_slow_headers() {
		let good = header("203.0.113.7:5000", "10.0.0.1:9443", &[]).await;

		let mut local = good.clone();
		local[12] = 0x20;
		assert_eq!(read(&local).await, Err(HeaderReject::Local));

		assert_eq!(
			read(b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\r\n").await,
			Err(HeaderReject::V1)
		);

		let mut bad_sig = good.clone();
		bad_sig[3] = 0;
		assert_eq!(read(&bad_sig).await, Err(HeaderReject::Invalid));

		let mut v1_version = good.clone();
		v1_version[12] = 0x11;
		assert_eq!(read(&v1_version).await, Err(HeaderReject::Invalid));

		let mut udp = good.clone();
		udp[13] = 0x12;
		assert_eq!(read(&udp).await, Err(HeaderReject::Invalid));

		let mut unspec = good.clone();
		unspec[13] = 0x00;
		assert_eq!(read(&unspec).await, Err(HeaderReject::Invalid));

		let mut short_len = good.clone();
		short_len[14..16].copy_from_slice(&8u16.to_be_bytes());
		assert_eq!(
			read(&short_len).await,
			Err(HeaderReject::Invalid),
			"IPv4 block under 12 bytes"
		);

		let mut v6_short = good.clone();
		v6_short[13] = 0x21; // claims IPv6 with a 12-byte block
		assert_eq!(read(&v6_short).await, Err(HeaderReject::Invalid));

		let mut oversized = good.clone();
		oversized[14..16].copy_from_slice(&((MAX_PAYLOAD + 1) as u16).to_be_bytes());
		assert_eq!(read(&oversized).await, Err(HeaderReject::Invalid));

		assert_eq!(
			read(&good[..20]).await,
			Err(HeaderReject::Invalid),
			"truncated"
		);

		let (mut slow, mut writer) = tokio::io::duplex(64);
		use tokio::io::AsyncWriteExt;
		writer.write_all(&good[..10]).await.unwrap();
		assert_eq!(
			read_proxy_v2(&mut slow, Duration::from_millis(50)).await,
			Err(HeaderReject::Timeout)
		);
	}

	#[tokio::test]
	async fn a_local_header_with_route_names_is_a_load_query() {
		let names = ["app.example.com", "b.example.com"];
		let mut bytes = encode_load_query(&names);
		bytes.extend_from_slice(b"ignored");
		let mut input = &bytes[..];
		assert_eq!(
			read_proxy_v2(&mut input, Duration::from_secs(1)).await,
			Ok(Header::LoadQuery(vec![
				Some("app.example.com".into()),
				Some("b.example.com".into())
			]))
		);
		assert_eq!(input, b"ignored", "only the header is consumed");

		// Other TLVs are skipped; a name that is not a DNS name keeps its place, unanswerable.
		let mut tlvs = vec![0x02, 0, 3, b'x', b'y', b'z'];
		for name in [&b"ok.test"[..], "é.test".as_bytes(), b"a b", b""] {
			tlvs.push(LOAD_QUERY_TLV);
			tlvs.extend_from_slice(&(name.len() as u16).to_be_bytes());
			tlvs.extend_from_slice(name);
		}
		let mut local = header("203.0.113.7:5000", "10.0.0.1:9443", &[]).await;
		local[12] = 0x20;
		local[14..16].copy_from_slice(&((12 + tlvs.len()) as u16).to_be_bytes());
		local.extend_from_slice(&tlvs);
		assert_eq!(
			read_header(&local).await,
			Ok(Header::LoadQuery(vec![
				Some("ok.test".into()),
				None,
				None,
				None
			]))
		);
	}

	#[tokio::test]
	async fn load_queries_beyond_the_receivers_bounds_are_rejected() {
		let names: Vec<String> = (0..=MAX_QUERY_NAMES)
			.map(|i| format!("n{i}.test"))
			.collect();
		assert_eq!(
			read_header(&encode_load_query(&names)).await,
			Err(HeaderReject::Invalid),
			"more names than one query may carry"
		);
		let at_limit = encode_load_query(&names[..MAX_QUERY_NAMES]);
		assert!(matches!(
			read_header(&at_limit).await,
			Ok(Header::LoadQuery(n)) if n.len() == MAX_QUERY_NAMES
		));

		let mut oversized = encode_load_query(&["a.test"]);
		oversized[14..16].copy_from_slice(&((MAX_LOCAL_PAYLOAD + 1) as u16).to_be_bytes());
		assert_eq!(read_header(&oversized).await, Err(HeaderReject::Invalid));

		let mut truncated_tlv = encode_load_query(&["a.test"]);
		truncated_tlv[17..19].copy_from_slice(&200u16.to_be_bytes()); // more than the payload holds
		assert_eq!(
			read_header(&truncated_tlv).await,
			Err(HeaderReject::Invalid)
		);

		let mut unix = encode_load_query(&["a.test"]);
		unix[13] = 0x31;
		assert_eq!(read_header(&unix).await, Err(HeaderReject::Invalid));

		assert_eq!(
			read_header(&encode_load_query::<&str>(&[])).await,
			Err(HeaderReject::Local),
			"a LOCAL without names is the plain health check it always was"
		);
	}

	#[test]
	fn load_answers_round_trip_and_anything_else_is_unusable() {
		let answer = encode_load_answer(&[Some(734), None, Some(1000), Some(0)]);
		assert_eq!(answer, b"SYMPHONY-LOAD/1\n734\n-\n1000\n0\n");
		assert_eq!(
			parse_load_answer(&answer, 4),
			Some(vec![Some(734), None, Some(1000), Some(0)])
		);
		assert_eq!(parse_load_answer(&answer, 3), None, "count mismatch");
		assert_eq!(
			parse_load_answer(b"", 1),
			None,
			"a 1.5.0 peer closes without a byte"
		);
		assert_eq!(parse_load_answer(b"SYMPHONY-LOAD/1\n1001\n", 1), None);
		assert_eq!(parse_load_answer(b"SYMPHONY-LOAD/1\n+12\n", 1), None);
		assert_eq!(
			parse_load_answer(b"SYMPHONY-LOAD/1\n12", 1),
			None,
			"truncated"
		);
		assert_eq!(parse_load_answer(b"SYMPHONY-LOAD/2\n12\n", 1), None);
		let long = [b"SYMPHONY-LOAD/1\n".to_vec(), vec![b'1'; 64]].concat();
		assert_eq!(parse_load_answer(&long, 1), None);
		assert!(encode_load_answer(&[Some(1000); 3]).len() <= max_load_answer_len(3));
	}

	#[test]
	fn trusted_sources_match_ipv4_mapped_peers_and_empty_trusts_nobody() {
		let state = IngressState::new(
			SourceAllowlist::parse_required(&["10.0.0.0/8".into()], "trustedSources").unwrap(),
		);
		assert!(state.trusts("10.1.2.3".parse().unwrap()));
		assert!(state.trusts("::ffff:10.1.2.3".parse().unwrap()));
		assert!(!state.trusts("192.0.2.1".parse().unwrap()));

		state.set_trusted(SourceAllowlist::parse_required(&[], "trustedSources").unwrap());
		assert!(!state.trusts("10.1.2.3".parse().unwrap()));
		assert!(SourceAllowlist::parse_required(&["not-a-cidr".into()], "trustedSources").is_err());
	}
}
