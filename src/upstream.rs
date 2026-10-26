use crate::balancer::{BalancerGuard, SlotHealth, UdsBalancer};
use crate::router::Destination;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UnixStream};
use tokio::time::timeout;

/// An established connection to an upstream server.
pub enum UpstreamStream {
	Tcp(TcpStream),
	Uds {
		stream: UnixStream,
		/// Keep the guard alive for the duration of the connection.
		_guard: BalancerGuard,
	},
}

/// Connect to an upstream destination.
/// `peer_ip` is passed to UDS balancers for IP affinity.
/// `connect_timeout` caps the time spent waiting for the connection, across every slot tried.
/// `tcp_health` is a failover route's state for a TCP destination; UDS slots carry their own.
pub async fn connect(
	destination: &Destination,
	peer_ip: Option<IpAddr>,
	connect_timeout: Duration,
	tcp_health: Option<&SlotHealth>,
) -> crate::error::Result<UpstreamStream> {
	match destination {
		Destination::Tcp(addr) => {
			let observed = tcp_health.map_or(0, |h| h.refused_at());
			let result = timeout(connect_timeout, TcpStream::connect(addr))
				.await
				.unwrap_or_else(|_| Err(connect_timed_out()));
			if let Some(health) = tcp_health {
				match &result {
					Ok(_) if observed != 0 => {
						health.clear_if_unchanged(observed);
					}
					Err(e) if is_refusal(e) => health.mark_refused(),
					_ => {}
				}
			}
			let stream = result?;
			stream.set_nodelay(true)?;
			Ok(UpstreamStream::Tcp(stream))
		}
		Destination::UdsSet(balancer) => connect_uds(balancer, peer_ip, connect_timeout).await,
	}
}

fn connect_timed_out() -> std::io::Error {
	std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream connect timeout")
}

/// The failures that say "nothing is accepting here": a stopped listener, a socket file that is
/// gone, a listener that cannot take the connection in time — or, for a Unix socket, a full accept
/// queue, which a non-blocking connect reports at once as `WouldBlock` instead of waiting.
pub fn is_refusal(e: &std::io::Error) -> bool {
	matches!(
		e.kind(),
		std::io::ErrorKind::ConnectionRefused
			| std::io::ErrorKind::NotFound
			| std::io::ErrorKind::TimedOut
			| std::io::ErrorKind::WouldBlock
	)
}

/// Connect to the picked slot; on a refusal try each remaining slot once, best score first, all
/// within one `connect_timeout`. One dead worker socket then costs a failed connect instead of
/// the client's connection.
async fn connect_uds(
	balancer: &Arc<UdsBalancer>,
	peer_ip: Option<IpAddr>,
	connect_timeout: Duration,
) -> crate::error::Result<UpstreamStream> {
	let mut idx = balancer.pick(peer_ip).ok_or_else(|| {
		crate::error::SymphonyError::Config("UDS balancer has no sockets configured".into())
	})?;
	let deadline = tokio::time::Instant::now() + connect_timeout;
	// Allocated only once a slot has refused.
	let mut tried: Vec<bool> = Vec::new();

	loop {
		let path = balancer.path(idx);
		let health = balancer.health(idx);
		// Read before connecting: clearing only this refusal means a connect that raced a newer
		// one cannot erase it, and an accepting slot costs no write.
		let observed = health.map_or(0, |h| h.refused_at());
		let result = tokio::time::timeout_at(deadline, UnixStream::connect(path.as_ref()))
			.await
			.unwrap_or_else(|_| Err(connect_timed_out()));
		match result {
			Ok(stream) => {
				if let (Some(h), true) = (health, observed != 0) {
					h.clear_if_unchanged(observed);
				}
				if !tried.is_empty() {
					balancer.rebind_affinity(peer_ip, idx);
				}
				// The guard increments the counter on construction and decrements on drop.
				let guard = BalancerGuard::new(balancer.clone(), path.to_string());
				return Ok(UpstreamStream::Uds {
					stream,
					_guard: guard,
				});
			}
			Err(e) if is_refusal(&e) => {
				if let Some(h) = health {
					h.mark_refused();
				}
				if tried.is_empty() {
					tried.resize(balancer.slot_count(), false);
				}
				tried[idx] = true;
				match balancer.next_untried(&tried) {
					Some(next) if tokio::time::Instant::now() < deadline => idx = next,
					_ => return Err(e.into()),
				}
			}
			Err(e) => return Err(e.into()),
		}
	}
}

/// Write a PROXY protocol v1 header so the backend can recover the real client
/// IP and port.
///
/// Format: `PROXY TCP4 <src-ip> <dst-ip> <src-port> <dst-port>\r\n`
pub async fn write_proxy_v1_header<W: tokio::io::AsyncWrite + Unpin>(
	stream: &mut W,
	peer_addr: SocketAddr,
) -> std::io::Result<()> {
	let (proto, src_ip, dst_ip) = match peer_addr.ip() {
		IpAddr::V4(ip) => ("TCP4", ip.to_string(), "127.0.0.1".to_string()),
		// Unwrap IPv4-mapped IPv6 (::ffff:1.2.3.4) to plain TCP4 so backends that
		// parse the PROXY header (HAProxy, nginx) receive a well-formed IPv4 address.
		IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
			Some(v4) => ("TCP4", v4.to_string(), "127.0.0.1".to_string()),
			None => ("TCP6", ip.to_string(), "::1".to_string()),
		},
	};
	// dst-port is 0 — a placeholder; the backend only reads src-ip and src-port.
	let header = format!("PROXY {proto} {src_ip} {dst_ip} {} 0\r\n", peer_addr.port());
	stream.write_all(header.as_bytes()).await
}

/// The 12-byte PROXY protocol v2 signature (`\r\n\r\n\0\r\nQUIT\n`).
const PROXY_V2_SIGNATURE: [u8; 12] = [
	0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

/// PP2 TLV type carrying the JA3 fingerprint. HAProxy reserves the 0xE0–0xEF range for
/// private/experimental TLVs (`PP2_TYPE_MIN_CUSTOM`); there is no registered type for JA3/JA4.
pub const PP2_TYPE_JA3: u8 = 0xE0;
/// PP2 TLV type carrying the JA4 fingerprint.
pub const PP2_TYPE_JA4: u8 = 0xE1;
/// PP2 TLV type carrying the mTLS client certificate chain: one TLV per certificate,
/// DER-encoded, leaf first (also in the 0xE0–0xEF custom range).
pub const PP2_TYPE_CLIENT_CERT: u8 = 0xE2;

// Standard PP2 TLV types (spec §2.2.x)
pub const PP2_TYPE_ALPN: u8 = 0x01;
pub const PP2_TYPE_AUTHORITY: u8 = 0x02;
pub const PP2_TYPE_SSL: u8 = 0x20;
pub const PP2_SUBTYPE_SSL_VERSION: u8 = 0x21;
pub const PP2_SUBTYPE_SSL_CIPHER: u8 = 0x23;
// PP2_TYPE_SSL `client` bit field
pub const PP2_CLIENT_SSL: u8 = 0x01;
pub const PP2_CLIENT_CERT_CONN: u8 = 0x02;

/// Normalized address bytes for a PROXY v2 address block, IPv4-mapped IPv6 unwrapped to v4
/// so the emitted family matches the v1 path's behaviour.
enum V2Addr {
	V4([u8; 4]),
	V6([u8; 16]),
}

fn normalize_v2_addr(ip: IpAddr) -> V2Addr {
	match ip {
		IpAddr::V4(v4) => V2Addr::V4(v4.octets()),
		IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
			Some(v4) => V2Addr::V4(v4.octets()),
			None => V2Addr::V6(v6.octets()),
		},
	}
}

/// Write a PROXY protocol v2 (binary) header so the backend can recover the real client
/// address, plus any `tlvs` (type, value) appended to the TLV section — used to carry the
/// client TLS fingerprint and mTLS facts downstream. TLVs with an empty value are skipped.
///
/// `local_addr` is the address the client connected to (the destination). When absent, or of a
/// different family than the source, a family-matched placeholder is used; the source address —
/// the field backends actually consume — is always accurate.
pub async fn write_proxy_v2_header<W: tokio::io::AsyncWrite + Unpin>(
	stream: &mut W,
	peer_addr: SocketAddr,
	local_addr: Option<SocketAddr>,
	tlvs: &[(u8, &[u8])],
) -> std::io::Result<()> {
	let src = normalize_v2_addr(peer_addr.ip());
	let dst = local_addr.map(|a| normalize_v2_addr(a.ip()));
	let dst_port = local_addr.map(|a| a.port()).unwrap_or(0);

	let mut out = Vec::with_capacity(28);
	out.extend_from_slice(&PROXY_V2_SIGNATURE);
	out.push(0x21); // version 2 (high nibble) | PROXY command (low nibble)

	// Address block. The family/proto byte is (family << 4) | transport; transport is
	// STREAM (0x1). Source family wins; a differing/absent dst falls back to loopback.
	let addr_block: Vec<u8> = match src {
		V2Addr::V4(src_ip) => {
			out.push(0x11); // AF_INET | STREAM
			let dst_ip = match dst {
				Some(V2Addr::V4(ip)) => ip,
				_ => [127, 0, 0, 1],
			};
			let mut b = Vec::with_capacity(12);
			b.extend_from_slice(&src_ip);
			b.extend_from_slice(&dst_ip);
			b.extend_from_slice(&peer_addr.port().to_be_bytes());
			b.extend_from_slice(&dst_port.to_be_bytes());
			b
		}
		V2Addr::V6(src_ip) => {
			out.push(0x21); // AF_INET6 | STREAM
			let dst_ip = match dst {
				Some(V2Addr::V6(ip)) => ip,
				_ => std::net::Ipv6Addr::LOCALHOST.octets(),
			};
			let mut b = Vec::with_capacity(36);
			b.extend_from_slice(&src_ip);
			b.extend_from_slice(&dst_ip);
			b.extend_from_slice(&peer_addr.port().to_be_bytes());
			b.extend_from_slice(&dst_port.to_be_bytes());
			b
		}
	};

	// TLV section, appended after the address block.
	let mut tlv_block = Vec::new();
	for (ty, bytes) in tlvs {
		if bytes.is_empty() {
			continue;
		}
		// TLV and header length fields are u16; refuse to silently truncate an oversized value.
		let tlv_len: u16 = bytes.len().try_into().map_err(|_| {
			std::io::Error::new(
				std::io::ErrorKind::InvalidInput,
				"PROXY v2 TLV value exceeds 65535 bytes",
			)
		})?;
		tlv_block.push(*ty);
		tlv_block.extend_from_slice(&tlv_len.to_be_bytes());
		tlv_block.extend_from_slice(bytes);
	}

	// 16-bit length of everything after the 16-byte fixed header (address block + TLVs).
	let len: u16 = (addr_block.len() + tlv_block.len())
		.try_into()
		.map_err(|_| {
			std::io::Error::new(
				std::io::ErrorKind::InvalidInput,
				"PROXY v2 header exceeds 65535 bytes",
			)
		})?;
	out.extend_from_slice(&len.to_be_bytes());
	out.extend_from_slice(&addr_block);
	out.extend_from_slice(&tlv_block);

	stream.write_all(&out).await
}

// ── tokio::io::AsyncRead + AsyncWrite impls via delegation ────────────────────
// We need UpstreamStream to work with copy_bidirectional.
// The cleanest approach is to use tokio's split + Box<dyn ...> or an enum dispatch.
// We use a concrete enum with manual pin-projection via tokio::io::copy_bidirectional
// on the inner streams, invoked from proxy_conn.rs by matching on the variant.
//
// This avoids the overhead of dynamic dispatch on every read/write call.
// proxy_conn.rs handles the match and calls the appropriate copy_bidirectional.

#[cfg(test)]
mod tests {
	use super::*;
	use crate::balancer::UdsSlotSpec;

	fn socket_dir(name: &str) -> std::path::PathBuf {
		let dir = std::env::temp_dir().join(format!("symphony-{name}-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		dir
	}

	fn balancer(paths: &[&std::path::Path], affinity: bool) -> UdsBalancer {
		let slots = paths
			.iter()
			.map(|p| UdsSlotSpec {
				path: p.to_str().unwrap().to_string(),
				pid: None,
				tid: None,
			})
			.collect();
		UdsBalancer::new(slots, affinity, 60_000)
	}

	async fn connected_path(dest: &Destination, ip: Option<IpAddr>) -> Option<String> {
		match connect(dest, ip, Duration::from_secs(1), None).await {
			Ok(UpstreamStream::Uds { stream, .. }) => Some(
				stream
					.peer_addr()
					.unwrap()
					.as_pathname()?
					.to_str()?
					.to_string(),
			),
			_ => None,
		}
	}

	#[tokio::test]
	async fn a_refusing_slot_falls_through_to_the_next_without_tracking() {
		let dir = socket_dir("fallthrough");
		let dead = dir.join("dead.sock"); // never bound: ENOENT
		let live = dir.join("live.sock");
		let _listener = tokio::net::UnixListener::bind(&live).unwrap();
		let ip: IpAddr = "192.0.2.1".parse().unwrap();
		let bal = Arc::new(balancer(&[&dead, &live], true));
		let dest = Destination::UdsSet(bal.clone());
		for _ in 0..3 {
			assert_eq!(
				connected_path(&dest, Some(ip)).await.as_deref(),
				live.to_str()
			);
		}
		assert_eq!(
			bal.pick(Some(ip)),
			Some(1),
			"affinity rebinds to the slot that accepted"
		);
		assert!(
			!bal.all_refusing(),
			"an untracked balancer never reports down"
		);
	}

	#[tokio::test]
	async fn tracked_slots_are_skipped_once_refusing_and_down_when_all_refuse() {
		let dir = socket_dir("tracked");
		let a = dir.join("a.sock");
		let b = dir.join("b.sock");
		let listener = tokio::net::UnixListener::bind(&b).unwrap();
		let bal = Arc::new(balancer(&[&a, &b], false).with_health(None));
		let dest = Destination::UdsSet(bal.clone());

		assert_eq!(connected_path(&dest, None).await.as_deref(), b.to_str());
		assert!(bal.health(0).unwrap().refusing());
		assert!(!bal.health(1).unwrap().refusing());
		assert_eq!(
			bal.pick(None),
			Some(1),
			"the refusing slot is no longer picked first"
		);
		assert!(!bal.all_refusing());

		drop(listener);
		std::fs::remove_file(&b).unwrap();
		assert!(connected_path(&dest, None).await.is_none());
		assert!(bal.all_refusing());

		let rebuilt = balancer(&[&a, &b], false).with_health(Some(&bal));
		assert!(rebuilt.all_refusing(), "a rebuild keeps the refusals");
		assert!(Arc::ptr_eq(
			rebuilt.health(0).unwrap(),
			bal.health(0).unwrap()
		));

		let _listener = tokio::net::UnixListener::bind(&a).unwrap();
		let observed = bal.health(0).unwrap().refused_at();
		assert!(bal.health(0).unwrap().clear_if_unchanged(observed));
		assert!(
			!rebuilt.all_refusing(),
			"clearing the shared state reaches the rebuilt table"
		);
	}

	#[tokio::test]
	async fn a_tcp_destination_marks_its_health_only_when_given_one() {
		let closed = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
		let addr = closed.local_addr().unwrap();
		drop(closed);
		let dest = Destination::Tcp(addr);
		let health = SlotHealth::default();
		assert!(connect(&dest, None, Duration::from_secs(1), Some(&health))
			.await
			.is_err());
		assert!(health.refusing());
		let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
		assert!(connect(&dest, None, Duration::from_secs(1), Some(&health))
			.await
			.is_ok());
		assert!(!health.refusing());
		drop(listener);
	}

	// A JA3-shaped value (32 hex chars) for TLV assertions.
	const JA3: &str = "0123456789abcdef0123456789abcdef";

	#[tokio::test]
	async fn v2_header_ipv4_with_ja3_tlv() {
		let peer: SocketAddr = "192.168.1.5:51000".parse().unwrap();
		let local: SocketAddr = "10.0.0.1:443".parse().unwrap();
		let mut out: Vec<u8> = Vec::new();
		write_proxy_v2_header(
			&mut out,
			peer,
			Some(local),
			&[(PP2_TYPE_JA3, JA3.as_bytes())],
		)
		.await
		.unwrap();

		// Fixed 16-byte header.
		assert_eq!(&out[0..12], &PROXY_V2_SIGNATURE);
		assert_eq!(out[12], 0x21, "version 2 | PROXY command");
		assert_eq!(out[13], 0x11, "AF_INET | STREAM");
		let declared_len = u16::from_be_bytes([out[14], out[15]]) as usize;
		assert_eq!(
			out.len(),
			16 + declared_len,
			"declared length covers the rest"
		);

		// IPv4 address block: src(4) dst(4) sport(2) dport(2).
		assert_eq!(&out[16..20], &[192, 168, 1, 5]);
		assert_eq!(&out[20..24], &[10, 0, 0, 1]);
		assert_eq!(u16::from_be_bytes([out[24], out[25]]), 51000);
		assert_eq!(u16::from_be_bytes([out[26], out[27]]), 443);

		// TLV: type(1) len(2) value.
		assert_eq!(out[28], PP2_TYPE_JA3);
		assert_eq!(u16::from_be_bytes([out[29], out[30]]) as usize, JA3.len());
		assert_eq!(&out[31..31 + JA3.len()], JA3.as_bytes());
		assert_eq!(out.len(), 31 + JA3.len(), "no trailing bytes");
	}

	#[tokio::test]
	async fn v2_header_skips_empty_tlv_and_defaults_dst() {
		let peer: SocketAddr = "203.0.113.9:1234".parse().unwrap();
		let mut out: Vec<u8> = Vec::new();
		// Empty fingerprint value (unparsed ClientHello) and no local_addr.
		write_proxy_v2_header(&mut out, peer, None, &[(PP2_TYPE_JA3, b"")])
			.await
			.unwrap();

		let declared_len = u16::from_be_bytes([out[14], out[15]]) as usize;
		assert_eq!(declared_len, 12, "address block only, empty TLV skipped");
		assert_eq!(out.len(), 28);
		assert_eq!(&out[20..24], &[127, 0, 0, 1], "dst defaults to loopback");
		assert_eq!(
			u16::from_be_bytes([out[26], out[27]]),
			0,
			"dst port defaults to 0"
		);
	}

	#[tokio::test]
	async fn v2_header_unwraps_ipv4_mapped_ipv6() {
		// ::ffff:1.2.3.4 must emit as AF_INET, matching the v1 path.
		let peer: SocketAddr = "[::ffff:1.2.3.4]:9000".parse().unwrap();
		let mut out: Vec<u8> = Vec::new();
		write_proxy_v2_header(&mut out, peer, None, &[])
			.await
			.unwrap();
		assert_eq!(out[13], 0x11, "IPv4-mapped IPv6 collapses to AF_INET");
		assert_eq!(&out[16..20], &[1, 2, 3, 4]);
	}

	#[tokio::test]
	async fn v2_header_ipv6() {
		let peer: SocketAddr = "[2001:db8::1]:8443".parse().unwrap();
		let mut out: Vec<u8> = Vec::new();
		write_proxy_v2_header(&mut out, peer, None, &[])
			.await
			.unwrap();
		assert_eq!(out[13], 0x21, "AF_INET6 | STREAM");
		let declared_len = u16::from_be_bytes([out[14], out[15]]) as usize;
		assert_eq!(declared_len, 36, "IPv6 address block is 36 bytes");
		assert_eq!(
			&out[16..32],
			&std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).octets()
		);
	}
}
