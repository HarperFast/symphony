//! The receiving end of peer failover: a TLS listener that admits only `trustedSources`, requires a
//! PROXY v2 header, and takes the client address from it.

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

/// Read exactly one PROXY v2 header and return its source address. Reads, rather than peeks, so
/// the ClientHello peek that follows starts on the first byte after it. TLVs are read past and
/// ignored: the peer terminates TLS itself and needs no TLS facts from the forwarding node.
pub async fn read_proxy_v2<S: AsyncRead + Unpin>(
	stream: &mut S,
	limit: Duration,
) -> Result<SocketAddr, HeaderReject> {
	let read = async {
		let mut fixed = [0u8; 16];
		stream
			.read_exact(&mut fixed)
			.await
			.map_err(|_| HeaderReject::Invalid)?;
		let len = parse_fixed(&fixed)?;
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
		parse_source(fixed[13], &addresses[..addr_len])
	};
	tokio::time::timeout(limit, read)
		.await
		.unwrap_or(Err(HeaderReject::Timeout))
}

fn parse_fixed(fixed: &[u8; 16]) -> Result<usize, HeaderReject> {
	if fixed.starts_with(b"PROXY ") {
		return Err(HeaderReject::V1);
	}
	if fixed[..12] != SIGNATURE || fixed[12] >> 4 != 2 {
		return Err(HeaderReject::Invalid);
	}
	match fixed[12] & 0x0F {
		0x1 => {}
		0x0 => return Err(HeaderReject::Local),
		_ => return Err(HeaderReject::Invalid),
	}
	let len = u16::from_be_bytes([fixed[14], fixed[15]]) as usize;
	let min = match fixed[13] {
		0x11 => 12, // TCP over IPv4
		0x21 => 36, // TCP over IPv6
		_ => return Err(HeaderReject::Invalid),
	};
	if len < min || len > MAX_PAYLOAD {
		return Err(HeaderReject::Invalid);
	}
	Ok(len)
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

	async fn read(bytes: &[u8]) -> Result<SocketAddr, HeaderReject> {
		let mut input = bytes;
		read_proxy_v2(&mut input, Duration::from_secs(1)).await
	}

	#[tokio::test]
	async fn reads_ipv4_and_leaves_the_following_bytes() {
		let mut bytes = header("203.0.113.7:5000", "10.0.0.1:9443", &[]).await;
		bytes.extend_from_slice(b"\x16\x03\x01rest");
		let mut input = &bytes[..];
		let src = read_proxy_v2(&mut input, Duration::from_secs(1))
			.await
			.unwrap();
		assert_eq!(src, "203.0.113.7:5000".parse().unwrap());
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
		assert_eq!(src, "203.0.113.7:5000".parse().unwrap());
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
