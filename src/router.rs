use crate::balancer::{UdsBalancer, UdsSlotSpec};
use crate::metrics::RouteMetrics;
use crate::tls::{CertSpec, MtlsSpec, TlsConfigCache};
use arc_swap::ArcSwap;
use rustls::ServerConfig;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now_ns() -> u64 {
	SystemTime::now()
		.duration_since(UNIX_EPOCH)
		.unwrap_or(Duration::ZERO)
		.as_nanos() as u64
}

// ── Per-route global token bucket ─────────────────────────────────────────────

/// A route-global (not per-IP) token bucket that caps the rate of new
/// connections accepted for a single route.  Uses the same fixed-point ×1000
/// CAS pattern as `protection.rs`.
pub struct RouteTokenBucket {
	/// Token count in fixed-point ×1000.  Max = `burst_fp`.
	tokens: AtomicU32,
	last_refill_ns: AtomicU64,
	/// Tokens added per nanosecond (= cps / 1e9).
	rate_per_ns: f64,
	/// Bucket ceiling in fixed-point ×1000.
	burst_fp: u32,
}

impl RouteTokenBucket {
	pub fn new(cps: f64, burst: Option<f64>) -> Self {
		let burst_fp = ((burst.unwrap_or(cps)).max(1.0) * 1000.0) as u32;
		Self {
			tokens: AtomicU32::new(burst_fp),
			last_refill_ns: AtomicU64::new(now_ns()),
			rate_per_ns: cps / 1_000_000_000.0,
			burst_fp,
		}
	}

	/// Attempt to consume one token.  Returns `false` when the bucket is empty
	/// (caller should drop the connection).
	pub fn try_acquire(&self) -> bool {
		const ONE_TOKEN: u32 = 1000; // fixed-point ×1000 representation of 1 token

		// Refill: add tokens proportional to elapsed time since last refill.
		let now = now_ns();
		loop {
			let last = self.last_refill_ns.load(Ordering::Relaxed);
			let elapsed = now.saturating_sub(last);
			let refill = (elapsed as f64 * self.rate_per_ns * 1000.0) as u32;
			if refill == 0 {
				break;
			}
			let old = self.tokens.load(Ordering::Relaxed);
			let new = old.saturating_add(refill).min(self.burst_fp);
			if self.tokens
				.compare_exchange(old, new, Ordering::Relaxed, Ordering::Relaxed)
				.is_ok()
			{
				let _ = self.last_refill_ns.compare_exchange(
					last, now, Ordering::Relaxed, Ordering::Relaxed,
				);
				break;
			}
			// CAS lost a race — retry
		}

		// Consume one token.
		loop {
			let tokens = self.tokens.load(Ordering::Relaxed);
			if tokens < ONE_TOKEN {
				return false;
			}
			if self.tokens
				.compare_exchange(
					tokens,
					tokens - ONE_TOKEN,
					Ordering::Relaxed,
					Ordering::Relaxed,
				)
				.is_ok()
			{
				return true;
			}
		}
	}
}

// ── Source address forwarding mode ────────────────────────────────────────────

/// How the real client IP is communicated to the upstream.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SourceAddressMode {
	/// No source address forwarding.
	None,
	/// Send a PROXY protocol v1 (text) header before any application data.
	ProxyProtocol,
	/// Send a PROXY protocol v2 (binary) header before any application data. The v2
	/// framing carries a TLV section, the carrier used for `ForwardFingerprint`.
	ProxyProtocolV2,
	/// Parse the beginning of the HTTP request and insert an X-Forwarded-For header.
	XForwardedFor,
}

/// Which client TLS fingerprint (if any) symphony forwards to the upstream so the backend
/// can act on it itself. Carrier depends on `SourceAddressMode`: a PROXY v2 TLV under
/// `ProxyProtocolV2`, otherwise an injected `X-JA3`/`X-JA4` HTTP header.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ForwardFingerprint {
	/// Do not forward a fingerprint.
	None,
	/// Forward the JA3 fingerprint.
	Ja3,
	/// Forward the JA4 fingerprint.
	Ja4,
}

// ── Route application protocol ────────────────────────────────────────────────

/// The application protocol of a route's byte stream, declared explicitly rather than
/// inferred from ALPN. ALPN alone cannot distinguish a native protocol that negotiates no
/// ALPN (e.g. MQTT) from an HTTPS client that simply offered none — both observe as `None`
/// (issue #38). Gates HTTP/1 header rewriting (`X-Forwarded-For` / `X-JA3` / `X-JA4`
/// injection): only a route that declares `Http` is ever fed to the header rewriter, and
/// only once TLS is terminated and h2 isn't negotiated (an h2 stream is excluded either way
/// — header injection would corrupt its binary frames).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RouteProtocol {
	/// Not HTTP: MQTT, a raw TCP protocol, or any application protocol symphony doesn't
	/// parse. Source-address forwarding is limited to the PROXY-protocol carriers.
	Opaque,
	/// The decrypted byte stream is HTTP/1.x — eligible for header-based forwarding modes.
	Http,
}

/// True when a route's forwarding config would need to inject a plaintext HTTP header
/// (`X-Forwarded-For`, or a header-carried `X-JA3`/`X-JA4`) rather than a carrier that works
/// on any byte stream. These are exactly the modes that require `RouteProtocol::Http` to be
/// declared explicitly — `forwardFingerprint` under `proxyProtocolV2` is exempt, since it
/// rides a TLV, not a header.
pub fn requires_http_protocol(mode: SourceAddressMode, fingerprint: ForwardFingerprint) -> bool {
	mode == SourceAddressMode::XForwardedFor
		|| (fingerprint != ForwardFingerprint::None && mode != SourceAddressMode::ProxyProtocolV2)
}

// ── Route destination ─────────────────────────────────────────────────────────

#[derive(Clone)]
pub enum Destination {
	Tcp(SocketAddr),
	UdsSet(Arc<UdsBalancer>),
}

// ── A resolved route ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct Route {
	/// Configured identity only; never derived from the client SNI/Host that selected this route.
	pub metric_identity: Arc<RouteMetricIdentity>,
	pub destination: Destination,
	/// Destination for connections that negotiated `h2` in ALPN, when the route
	/// has h2-marked upstreams. None = all protocols share `destination`.
	pub destination_h2: Option<Destination>,
	/// None = TLS passthrough (no termination)
	pub tls_config: Option<Arc<ServerConfig>>,
	pub terminate_tls: bool,
	pub suspended: bool,
	pub suspend_timeout: Duration,
	/// Optional global rate limiter for this route.
	pub rate_limiter: Option<Arc<RouteTokenBucket>>,
	/// How the real client IP is forwarded to the upstream.
	pub source_address_mode: SourceAddressMode,
	/// Which client TLS fingerprint (if any) is forwarded to the upstream.
	pub forward_fingerprint: ForwardFingerprint,
	/// The route's declared application protocol — gates HTTP/1 header rewriting.
	pub protocol: RouteProtocol,
}

pub struct RouteMetricIdentity {
	pub route: Arc<str>,
	pub group: Arc<str>,
	pub counters: Arc<RouteMetrics>,
}

impl RouteMetricIdentity {
	fn new(route: &str, group: &str) -> Self {
		Self { route: Arc::from(route), group: Arc::from(group), counters: Arc::new(RouteMetrics::default()) }
	}
}

// ── Route table ───────────────────────────────────────────────────────────────

/// True when `sni` matches exactly one left-most label against `suffix` (a wildcard's stored
/// suffix, without the `*.` prefix) — e.g. "foo.example.com" matches suffix "example.com" but
/// "a.b.example.com" does not.
fn wildcard_suffix_matches(sni: &str, suffix: &str) -> bool {
	if sni.len() <= suffix.len() + 1 {
		return false;
	}
	let dot_pos = sni.len() - suffix.len() - 1;
	let rest = &sni[sni.len() - suffix.len()..];
	let prefix = &sni[..dot_pos];
	!prefix.contains('.') && rest == suffix && sni.as_bytes()[dot_pos] == b'.'
}

pub struct RouteTable {
	exact: HashMap<Arc<str>, Route>,
	/// (suffix_without_star_dot, route) — "*.example.com" stored as "example.com"
	wildcard: Vec<(Arc<str>, Route)>,
	default: Option<Route>,
	/// All UdsBalancers that have at least one pid/tid-configured slot.
	/// Used by the CPU monitor task spawned in `proxy.rs::start()`.
	pub monitored_balancers: Vec<Arc<UdsBalancer>>,
	/// SNIs whose cert failed to build in this table. Carried across a hot-swap so a
	/// persistently-broken route is logged only on the good→bad transition, not every reconcile.
	failing_snis: HashSet<Arc<str>>,
	/// Exact SNIs dropped with no last-good route to carry forward (a subset of `failing_snis` —
	/// this excludes SNIs whose last-good route IS still present in `exact`/`wildcard` and
	/// serving traffic). `resolve()` must fail closed for these rather than falling through to a
	/// wildcard or default route: a route absent from `exact` because it was rejected is not the
	/// same as a route that was simply never configured, and letting the former silently match a
	/// broader wildcard would misroute that tenant's traffic to an unrelated upstream instead of
	/// refusing the connection.
	dropped_exact: HashSet<Arc<str>>,
	/// Wildcard suffixes (without the `*.` prefix) dropped with no last-good route — same
	/// fail-closed reasoning as `dropped_exact`, checked against incoming SNIs with the same
	/// suffix-matching rule as `wildcard` itself.
	dropped_wildcard: Vec<Arc<str>>,
}

impl RouteTable {
	/// Number of routes serving traffic, including the default route if one is configured.
	pub fn route_count(&self) -> usize {
		self.exact.len() + self.wildcard.len() + usize::from(self.default.is_some())
	}

	/// Number of SNIs whose cert failed to build in this table — either dropped, or serving a
	/// carried-forward last-good cert. Non-zero means a rotation needs attention.
	pub fn failing_route_count(&self) -> usize {
		self.failing_snis.len()
	}

	pub fn metric_identities(&self) -> Vec<Arc<RouteMetricIdentity>> {
		let mut identities: Vec<_> = self
			.exact
			.values()
			.chain(self.wildcard.iter().map(|(_, route)| route))
			.chain(self.default.iter())
			.map(|route| route.metric_identity.clone())
			.collect();
		identities.sort_unstable_by(|a, b| a.route.cmp(&b.route).then_with(|| a.group.cmp(&b.group)));
		identities
	}

	pub fn resolve(&self, sni: Option<&str>) -> Option<&Route> {
		let Some(sni) = sni else {
			return self.default.as_ref();
		};

		// A route rejected outright (no last-good to carry forward) must fail closed, not fall
		// through to a broader fallback: it was configured for this SNI, just rejected, which is
		// not the same as "no route was ever configured here." But a poison entry must only ever
		// suppress a fallback *broader* than itself — it must never shadow a route that is more
		// specific than the poison. So each dropped set is checked immediately after its
		// same-specificity live counterpart, not before it: a healthy exact route always wins over
		// a dropped wildcard at the same suffix (checking dropped_wildcard first would incorrectly
		// black-hole every exact route under a wildcard that happened to fail validation).

		// Exact, live or dropped — most specific, decided first.
		if let Some(r) = self.exact.get(sni) {
			return Some(r);
		}
		if self.dropped_exact.contains(sni) {
			return None;
		}

		// Wildcard, live or dropped — match exactly one left-most label against stored suffixes.
		// e.g. "foo.example.com" matches "*.example.com" but "a.b.example.com" does not.
		for (suffix, route) in &self.wildcard {
			if wildcard_suffix_matches(sni, suffix) {
				return Some(route);
			}
		}
		if self.dropped_wildcard.iter().any(|suffix| wildcard_suffix_matches(sni, suffix)) {
			return None;
		}

		self.default.as_ref()
	}

	/// Look up the route stored under the key a spec's SNI would insert to (the exact SNI,
	/// or the suffix of a `*.` wildcard) — not the resolve()-style match. Used to carry a
	/// last-good route forward across a hot-swap when the new cert transiently fails to build.
	fn get_for_spec_sni(&self, sni: &str) -> Option<&Route> {
		if let Some(suffix) = sni.strip_prefix("*.") {
			self.wildcard.iter().find(|(s, _)| s.as_ref() == suffix).map(|(_, r)| r)
		} else {
			self.exact.get(sni)
		}
	}
}

// ── Builder / config types ────────────────────────────────────────────────────

/// Raw JS-provided upstream specification.
#[derive(Clone, Debug)]
pub enum UpstreamSpec {
	Tcp { host: String, port: u16 },
	Uds {
		paths: Vec<String>,
		/// PID per path (parallel vec, same length as `paths`).
		pids: Vec<Option<u32>>,
		/// TID per path (parallel vec, same length as `paths`).
		tids: Vec<Option<u32>>,
		ip_affinity: bool,
		affinity_ttl_ms: u64,
		/// Application protocol this socket speaks ("h2" for a cleartext HTTP/2
		/// upstream, e.g. Harper's `-h2.sock` mirror). None = HTTP/1.x (historical).
		protocol: Option<String>,
	},
}

/// Raw JS-provided route configuration.
#[derive(Clone, Debug)]
pub struct RouteSpec {
	pub sni: String,
	pub metrics_group: String,
	pub upstreams: Vec<UpstreamSpec>,
	pub terminate_tls: bool,
	pub cert_pem: Option<Vec<u8>>,
	pub key_pem: Option<Vec<u8>>,
	pub mtls_ca_pem: Option<Vec<u8>>,
	pub require_client_cert: bool,
	pub suspended: bool,
	pub suspend_timeout_ms: u64,
	/// Optional global rate limit (connections per second) for this route.
	pub max_cps: Option<f64>,
	/// Token bucket burst ceiling (defaults to `max_cps` if not set).
	pub burst: Option<f64>,
	/// How the real client IP is forwarded to the upstream.
	pub source_address_mode: SourceAddressMode,
	/// Which client TLS fingerprint (if any) is forwarded to the upstream.
	pub forward_fingerprint: ForwardFingerprint,
	/// Advertise h2 in ALPN so clients can negotiate HTTP/2.
	pub http2: bool,
	/// The route's declared application protocol — gates HTTP/1 header rewriting. Validated
	/// against `source_address_mode`/`forward_fingerprint` at parse time (`proxy.rs`), so by
	/// the time a `RouteSpec` reaches `build_route` the combination is already known-valid.
	pub protocol: RouteProtocol,
}

/// Listener-level fallback cert/mTLS spec.
#[derive(Clone, Debug)]
pub struct ListenerTlsSpec {
	pub cert_pem: Option<Vec<u8>>,
	pub key_pem: Option<Vec<u8>>,
	pub mtls_ca_pem: Option<Vec<u8>>,
	pub require_client_cert: bool,
}

impl ListenerTlsSpec {
	pub fn empty() -> Self {
		Self {
			cert_pem: None,
			key_pem: None,
			mtls_ca_pem: None,
			require_client_cert: true,
		}
	}
}

/// Build a RouteTable from a list of route specs and a listener-level fallback.
///
/// `previous` is the currently-live table on a hot-swap (None on initial construction). When
/// a route's cert fails to build, its last-good route is carried forward from `previous` if
/// present, so a transient rotation mismatch keeps serving the old (still-valid) cert instead
/// of dropping the SNI.
pub fn build_route_table(
	specs: &[RouteSpec],
	listener_tls: &ListenerTlsSpec,
	previous: Option<&RouteTable>,
) -> crate::error::Result<RouteTable> {
	let mut cache = TlsConfigCache::new();
	let mut exact: HashMap<Arc<str>, Route> = HashMap::new();
	let mut wildcard: Vec<(Arc<str>, Route)> = Vec::new();
	let mut monitored_balancers: Vec<Arc<UdsBalancer>> = Vec::new();
	let mut failing_snis: HashSet<Arc<str>> = HashSet::new();
	let mut dropped_exact: HashSet<Arc<str>> = HashSet::new();
	let mut dropped_wildcard: Vec<Arc<str>> = Vec::new();

	for spec in specs {
		// The protocol/no-carrier declaration checks are validated before any cert/TLS work, and
		// deliberately never carried forward on a hot-swap even if a last-good route exists: unlike
		// a cert failure (a transient race between two non-atomic file writes that heals on its own
		// next reconcile), a missing declaration or a passthrough-with-no-carrier config is a
		// permanent config error — it never heals without a human editing the config. Applying
		// cert-style carry-forward to it would silently keep serving the *previous* route
		// indefinitely, including ignoring any other change (a new upstream, a cert rotation) the
		// same reconcile made to that route — the operator's `updateConfig` reports success while
		// their edit quietly never took effect.
		if let Err(e) = validate_route_protocol_declaration(spec) {
			let newly_failing = previous.is_none_or(|p| !p.failing_snis.contains(spec.sni.as_str()));
			failing_snis.insert(Arc::from(spec.sni.as_str()));
			if newly_failing {
				eprintln!("symphony: skipping route '{}': {}", spec.sni, e);
			}
			if let Some(suffix) = spec.sni.strip_prefix("*.") {
				dropped_wildcard.push(Arc::from(suffix));
			} else {
				dropped_exact.insert(Arc::from(spec.sni.as_str()));
			}
			continue;
		}

		// Isolate per-route failures: a single route whose cert can't be built (e.g. a
		// rotated key no longer matching an inlined chain → rustls KeyMismatch) must not
		// abort the whole table and take every other tenant on the port down with it.
		let mut route = match build_route(spec, listener_tls, &mut cache) {
			Ok(route) => route,
			Err(e) => {
				// Log only on the good→bad transition: a persistently-broken cert would
				// otherwise re-log on every reconcile, since each cert-file event rebuilds
				// the whole table.
				let newly_failing = previous.is_none_or(|p| !p.failing_snis.contains(spec.sni.as_str()));
				failing_snis.insert(Arc::from(spec.sni.as_str()));

				match previous.and_then(|p| p.get_for_spec_sni(&spec.sni)) {
					// On a hot-swap, a cert and key rotate as two non-atomic files, so a
					// transient mismatch mid-rotation is normal. Carry the previous route
					// forward *whole* (cert and upstreams) — intentional: its cert is still
					// valid, and the route heals on the next reconcile when the pair is
					// consistent. If the route's upstreams also changed in the same reconcile,
					// they too persist until then; that's the accepted cost of last-good.
					Some(prev) => {
						if newly_failing {
							eprintln!(
								"symphony: route '{}' failed to rebuild ({}); retaining last-good route",
								spec.sni, e
							);
						}
						prev.clone()
					}
					// No prior route (initial build, or a newly-added route): drop this SNI. It must
					// resolve to nothing, not silently fall through to a broader wildcard or the
					// default route — this SNI *was* configured, just rejected, which is a different
					// (and worse, if left unhandled) case than "no route was ever set up for it": a
					// dropped exact route shadowed by an unrelated wildcard would otherwise misroute
					// that tenant's traffic to a different upstream with no visible error.
					None => {
						if newly_failing {
							eprintln!("symphony: skipping route '{}': {}", spec.sni, e);
						}
						if let Some(suffix) = spec.sni.strip_prefix("*.") {
							dropped_wildcard.push(Arc::from(suffix));
						} else {
							dropped_exact.insert(Arc::from(spec.sni.as_str()));
						}
						continue;
					}
				}
			}
		};

		// Reusing by the full metric identity keeps ordinary cert/upstream reloads continuous
		// without moving historical counters when a route changes tenant groups.
		if let Some(previous_route) = previous.and_then(|table| table.get_for_spec_sni(&spec.sni)) {
			if previous_route.metric_identity.group.as_ref() == spec.metrics_group {
				route.metric_identity = previous_route.metric_identity.clone();
			}
		}

		// Collect UdsBalancers that have pid/tid slots for the monitor task.
		for dest in std::iter::once(&route.destination).chain(route.destination_h2.iter()) {
			if let Destination::UdsSet(ref bal) = dest {
				if bal.has_monitored_slots() {
					monitored_balancers.push(bal.clone());
				}
			}
		}

		if spec.sni.starts_with("*.") {
			let suffix: Arc<str> = Arc::from(&spec.sni[2..]);
			wildcard.push((suffix, route));
		} else {
			let key: Arc<str> = Arc::from(spec.sni.as_str());
			exact.insert(key, route);
		}
	}

	Ok(RouteTable { exact, wildcard, default: None, monitored_balancers, failing_snis, dropped_exact, dropped_wildcard })
}

/// The "no carrier" and "declare protocol: 'http'" requirements — checked in `build_route_table`
/// before `build_route` runs, and deliberately never carried forward on a hot-swap (see the call
/// site): unlike a cert-build failure, this is a permanent config error, not a transient race.
fn validate_route_protocol_declaration(spec: &RouteSpec) -> crate::error::Result<()> {
	let requires_http = requires_http_protocol(spec.source_address_mode, spec.forward_fingerprint);

	// Passthrough (terminateTls=false) never decrypts the stream, so a header-carried mode has no
	// carrier at all regardless of `protocol` — declaring 'http' wouldn't help. Checked before (and
	// distinct from) the declaration requirement below: it's not that the route mislabeled its
	// protocol, it's that no protocol declaration could make this work.
	if requires_http && !spec.terminate_tls {
		return Err(crate::error::SymphonyError::Config(format!(
			"route '{}': sourceAddressHeader 'xForwardedFor', or forwardFingerprint via an HTTP header (any mode other than 'proxyProtocolV2'), has no carrier when terminateTls=false (passthrough never decrypts the stream, so no header can be injected) — use sourceAddressHeader='proxyProtocolV2' (carries both source address and fingerprint), or remove forwardFingerprint",
			spec.sni
		)));
	}

	if requires_http && spec.protocol != RouteProtocol::Http {
		return Err(crate::error::SymphonyError::Config(format!(
			"route '{}': sourceAddressHeader 'xForwardedFor', or forwardFingerprint via an HTTP header (any mode other than 'proxyProtocolV2'), requires protocol: 'http' — declare it explicitly, or switch away from the header-carried mode: 'proxyProtocol'/'proxyProtocolV2' both work on any protocol for source-address forwarding, but only 'proxyProtocolV2' carries a fingerprint (v1 does not)",
			spec.sni
		)));
	}

	Ok(())
}

fn build_route(
	spec: &RouteSpec,
	listener_tls: &ListenerTlsSpec,
	cache: &mut TlsConfigCache,
) -> crate::error::Result<Route> {
	let tls_config = if spec.terminate_tls {
		let cert_pem = spec
			.cert_pem
			.as_deref()
			.or(listener_tls.cert_pem.as_deref())
			.ok_or_else(|| {
				crate::error::SymphonyError::Config(format!(
					"route '{}' has terminateTls=true but no cert provided",
					spec.sni
				))
			})?;
		let key_pem = spec
			.key_pem
			.as_deref()
			.or(listener_tls.key_pem.as_deref())
			.ok_or_else(|| {
				crate::error::SymphonyError::Config(format!(
					"route '{}' has terminateTls=true but no private key provided",
					spec.sni
				))
			})?;
		let cert_spec = CertSpec {
			cert_chain_pem: cert_pem.to_vec(),
			private_key_pem: key_pem.to_vec().into(),
		};

		let mtls_ca = spec
			.mtls_ca_pem
			.as_deref()
			.or(listener_tls.mtls_ca_pem.as_deref());
		let mtls_spec = mtls_ca.map(|ca| MtlsSpec {
			client_ca_pem: ca.to_vec(),
			require_client_cert: if spec.mtls_ca_pem.is_some() {
				spec.require_client_cert
			} else {
				listener_tls.require_client_cert
			},
		});

		Some(cache.get_or_build(&cert_spec, mtls_spec.as_ref(), spec.http2)?)
	} else {
		None
	};

	let (destination, destination_h2) = build_destinations(spec)?;

	// Header injection cannot apply to h2 frames; PROXY protocol rides before the
	// preface and works for both protocols. Any route that can carry h2 to an
	// upstream (a split h2 destination, OR http2 ALPN advertised so an h2 client's
	// preface flows to the default upstream) must not use XFF — enforce it rather
	// than splice a header into the middle of the connection preface.
	if (destination_h2.is_some() || (spec.http2 && spec.terminate_tls))
		&& spec.source_address_mode == SourceAddressMode::XForwardedFor
	{
		return Err(crate::error::SymphonyError::Config(format!(
			"route '{}': sourceAddressHeader 'xForwardedFor' cannot be combined with HTTP/2 (header injection would corrupt h2 frames); use 'proxyProtocol' or 'none'",
			spec.sni
		)));
	}
	if destination_h2.is_some() {
		if !spec.terminate_tls {
			return Err(crate::error::SymphonyError::Config(format!(
				"route '{}': h2-marked upstreams require terminateTls=true — in passthrough mode symphony never sees the negotiated ALPN, so it cannot dispatch by protocol",
				spec.sni
			)));
		}
		if !spec.http2 {
			eprintln!(
				"symphony: route '{}': has h2 upstreams but http2=false — clients will never negotiate h2, so those upstreams are unreachable",
				spec.sni
			);
		}
	} else if spec.http2 && spec.terminate_tls {
		eprintln!(
			"symphony: route '{}': http2=true with no h2-marked upstream — h2-negotiated connections are forwarded to the default upstream, which must itself speak HTTP/2",
			spec.sni
		);
	}

	let rate_limiter = spec
		.max_cps
		.map(|cps| Arc::new(RouteTokenBucket::new(cps, spec.burst)));

	Ok(Route {
		metric_identity: Arc::new(RouteMetricIdentity::new(&spec.sni, &spec.metrics_group)),
		destination,
		destination_h2,
		tls_config,
		terminate_tls: spec.terminate_tls,
		suspended: spec.suspended,
		suspend_timeout: Duration::from_millis(spec.suspend_timeout_ms.max(1)),
		rate_limiter,
		source_address_mode: spec.source_address_mode,
		forward_fingerprint: spec.forward_fingerprint,
		protocol: spec.protocol,
	})
}

/// Build the route's destinations: the default (h1) destination plus, when any
/// upstream is marked `protocol: "h2"`, a separate destination for connections
/// that negotiated h2 in ALPN.
fn build_destinations(spec: &RouteSpec) -> crate::error::Result<(Destination, Option<Destination>)> {
	// Suspended routes or routes with no upstreams use a placeholder TCP dest
	// that is replaced by resolveConnection() before any data flows.
	if spec.suspended || spec.upstreams.is_empty() {
		return Ok((Destination::Tcp("127.0.0.1:1".parse().unwrap()), None));
	}

	let is_h2 = |u: &UpstreamSpec| matches!(u, UpstreamSpec::Uds { protocol: Some(p), .. } if p == "h2");
	let h1_specs: Vec<&UpstreamSpec> = spec.upstreams.iter().filter(|u| !is_h2(u)).collect();
	let h2_specs: Vec<&UpstreamSpec> = spec.upstreams.iter().filter(|u| is_h2(u)).collect();

	if h1_specs.is_empty() {
		return Err(crate::error::SymphonyError::Config(format!(
			"route '{}': all upstreams are marked protocol 'h2' — at least one default (http/1.x) upstream is required for clients that do not negotiate h2",
			spec.sni
		)));
	}

	let destination = build_destination_for(&h1_specs)?;
	let destination_h2 = if h2_specs.is_empty() {
		None
	} else {
		Some(build_destination_for(&h2_specs)?)
	};
	Ok((destination, destination_h2))
}

fn build_destination_for(upstreams: &[&UpstreamSpec]) -> crate::error::Result<Destination> {
	let first = upstreams
		.first()
		.ok_or_else(|| crate::error::SymphonyError::Config("route has no upstreams".to_string()))?;
	match first {
		UpstreamSpec::Tcp { host, port } => {
			let addr: SocketAddr =
				format!("{host}:{port}").parse().map_err(crate::error::SymphonyError::AddrParse)?;
			Ok(Destination::Tcp(addr))
		}
		UpstreamSpec::Uds { .. } => {
			// Collect all UDS upstreams into a flat slot list.
			let mut slots: Vec<UdsSlotSpec> = Vec::new();
			let mut ip_affinity = false;
			let mut affinity_ttl_ms = 300_000u64;

			for u in upstreams {
				if let UpstreamSpec::Uds {
					paths,
					pids,
					tids,
					ip_affinity: aff,
					affinity_ttl_ms: ttl,
					..
				} = u
				{
					for (i, path) in paths.iter().enumerate() {
						slots.push(UdsSlotSpec {
							path: path.clone(),
							pid: pids.get(i).copied().flatten(),
							tid: tids.get(i).copied().flatten(),
						});
					}
					ip_affinity = *aff;
					affinity_ttl_ms = *ttl;
				}
			}
			Ok(Destination::UdsSet(Arc::new(UdsBalancer::new(
				slots,
				ip_affinity,
				affinity_ttl_ms,
			))))
		}
	}
}

// ── Live route table holder ───────────────────────────────────────────────────

pub struct LiveRouteTable(pub ArcSwap<RouteTable>);

impl LiveRouteTable {
	pub fn new(table: RouteTable) -> Arc<Self> {
		Arc::new(Self(ArcSwap::new(Arc::new(table))))
	}

	pub fn swap(&self, table: RouteTable) {
		self.0.store(Arc::new(table));
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	// A self-signed cert (CERT_A) and its matching key (KEY_A), plus an unrelated key
	// (KEY_B). Pairing CERT_A with KEY_B reproduces the production rustls KeyMismatch a
	// cert rotation causes (leaf pubkey ≠ private key).
	const CERT_A: &[u8] = b"-----BEGIN CERTIFICATE-----
MIIDNDCCAhygAwIBAgIUM+1LAIojftQSkEIBoBR0AV87XfowDQYJKoZIhvcNAQEL
BQAwGzEZMBcGA1UEAwwQZ29vZC5leGFtcGxlLmNvbTAeFw0yNjA3MDYxNTQ4MzBa
Fw0zNjA3MDMxNTQ4MzBaMBsxGTAXBgNVBAMMEGdvb2QuZXhhbXBsZS5jb20wggEi
MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCua7KJUHPYvO/PaqLDMrHGlEdd
pxkFGMifO87nj9QRnIpHcz+nWrdvH57QpBRdojBC/j9L2/ybaRVGM52OO5fJm1DH
4veD9axofkOGWBp1yPqDlxe0g/wlreWtAAMRVqGODw/OOvcDwnokWlLWfJ9lRKma
GQ8Pmd9iza19gnuLTc7OggqXK3wgqNA3A/OrciTIBp+Dcf8GdUIHiXmyMC0UaA14
2YzfVSnMd8Umhn41rHhMXk9Wedlp9FBeZHKLOW8i/vUOBdz0tm8sCK1xEqZIfIZg
EMUdu/VeJ0rvsQ6RFgooU3rmxVmvsMaJwHHQYuOOO1y+h6tTakwQ+6FIMbY7AgMB
AAGjcDBuMB0GA1UdDgQWBBQoUwNGmTQXq7HjxnbQQyojQYLFijAfBgNVHSMEGDAW
gBQoUwNGmTQXq7HjxnbQQyojQYLFijAPBgNVHRMBAf8EBTADAQH/MBsGA1UdEQQU
MBKCEGdvb2QuZXhhbXBsZS5jb20wDQYJKoZIhvcNAQELBQADggEBAKsI0WUT7Cx1
D81qwxrSGKONVsyPDalenIMRKQlx3SS4hhijMnwDCR23DLEXQVRAadwzHURx6qkx
nJW+C4Ete3KcEM8Y3pWUFV9OZCPoCh9LKj/wQdCkldSkT3vHKbovgefgxbEn0aSD
+FYsvd8jhGfyEs1JoU/58/rf2D/l6srNyn20ODTQ5AAMwh1IG8XjfhwpGm9gHwh2
DFtLpgH9/vMh9LPjXRc3Mdc4Idqoi6pSlswPXxshjhQncVXy1/RhEzfEtrM7BuzZ
ZlgCEToIkYUjQVGSygmQqFBbRC5EJAPb+Wpx8N5Y2+g/Q2qy2aPKXhIcOwFSrtbB
43vjnvisyZ0=
-----END CERTIFICATE-----
";

	const KEY_A: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCua7KJUHPYvO/P
aqLDMrHGlEddpxkFGMifO87nj9QRnIpHcz+nWrdvH57QpBRdojBC/j9L2/ybaRVG
M52OO5fJm1DH4veD9axofkOGWBp1yPqDlxe0g/wlreWtAAMRVqGODw/OOvcDwnok
WlLWfJ9lRKmaGQ8Pmd9iza19gnuLTc7OggqXK3wgqNA3A/OrciTIBp+Dcf8GdUIH
iXmyMC0UaA142YzfVSnMd8Umhn41rHhMXk9Wedlp9FBeZHKLOW8i/vUOBdz0tm8s
CK1xEqZIfIZgEMUdu/VeJ0rvsQ6RFgooU3rmxVmvsMaJwHHQYuOOO1y+h6tTakwQ
+6FIMbY7AgMBAAECggEAB3Mq1Hn2AaYEt7uamwFV3eEoIr7oC3NaUskIaFtfxgoh
wPygatZKUln59LD53+9Kgmyw9zKgWZtspGuHvrMpI43goGrNrTNXqYPNxzXCJx/D
d+q7pM2kKKy7kzQy0Oaosk0yKxL15co2YR9XaABWA3UwVG2lzHrmz9CM8CON1xy/
IHisFG0ydUcM/RJf8xyU4YO74ko/XSRnLaXpjzro+uMJI6Wkhz7ny6Z5SP9xbjwS
ZzzczOxjZlP11mpkEfapp1ircWLPp/IXcFXYTjrHgWXjO6W/LCYAJCZgf+eFuUrC
OeZ4QbRodt9D+j4IHBWReuD6Ey0i46OKPrvLKCBRQQKBgQDxscnPQSEIhLVfglUB
byILifk8nr1n8SWrInJ2yZKwoEOowuFgzIhQ1wSNvJI3X0K+2jtNTeuCQxzLFe11
I0+NTUmpBde3WGcvXAs3KW4aKlLqM6QniP7P60/WeYMGbWqPz06MiyVHFbY/s2Z5
/WOFt78H6hN1JcIl5S5rTdFLIQKBgQC4vo+ONGatoP7OmPW9ZEU0wuDxoWnsm538
qxbxCrHZ2183W7wFImjIbQl9zOwOttsmeKgPUFcdA1CMx0UvL3hkbiR+awI0W16u
E7tFo8zfTe0xVjsS+hMJJSO/2t5eZbydHHGNzArvuMMo9Ya3w+1J0b/O7WGZjv7o
rcjfKkFR2wKBgHxlmEwu5lSfEUb2KtBRJcGwovI7dZsA9/VMBoPzHagA5LIAk8Wh
n+uTr4lP7CXJxu26Htmb6EIkTraMM6qdoP1GMUpocm2wd3NduXwLu9qFvCVErRGY
JiZXo8Dsy65MNJOODIyztV0P5LyGlpDlBQs21oC5Toh2BaZBfhHGfJlhAoGAAigP
Suynqi0v7D9y1uQdvrDrqUZmEyH55SImIWgrjUx3PxEuD61IJdbH/pTuyHkv87IC
3DLm4WrRfOMylotqT1nNyT/8hZnvb/7A994inRSuyR2lkOIkaL3rPekTIWz0l6zm
Um5oTkYM2SSMjwaVdYAiSgsRUZaOuS6WIqy+mHMCgYAPnBR1Siot76IC1LvMtCKY
jNlP4EkR2mcBb/5QVbGHWO3N+8k5I6HUPRXtzKYOYWHimi6O2oQvo2VXYQiyVBvt
VoFdScNyywMI3pOWGUD+OixcgPt/EF9+XG77/jfrDAgHV8rGlin6OAysdi9NHynA
UKlOCXtHXb1XskMBV7W29w==
-----END PRIVATE KEY-----
";

	const KEY_B: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQCWxNE5Z315MdlX
Za+MKSJrdcJlm5zHfsBZ642On9Cc+oMe+U5+91RMUhiNt524CNvQyDMTntiD9wn7
zUaeQGZjP+wtUDcIG1S1EIXhoAWLWd+Jww/3WAYNxnauIW3QawlqH/aiJVxTgWB2
K0WjqkLM8T1A23uBSoJUl87f0wnLVctxyqF+dZ7QwqYvNcywnmeRnoNb//eKEttF
qhaxkxgdG72tpO65bAF2IGaQ3Sk0npmqD1TP5ZF1jGVr+uW+4TwAxazN7E+Cvyz3
IXdkTz/yj81vUZXQxK22Z3lgpXosBrFcrEYiy0/YIIdaOrPC3z9WEiXxI2eIxwWt
Nd7Kp4TFAgMBAAECggEAAeXeYGOeH71x5/i+ufv2k/W6ib7ovVYqI7ekY4w9ewxo
RCaNR2njpMZPytDp6lwqMDmk8vVH8nlUpdfSsMFMyKkQVw2wc6isa08W8F0sVLG/
76MF+24fPWMnMU/4auw+BRj76NShkeeKCFLJIKNPDfdndv6MUndWpqv2jbjBYc7g
ug3IyQPIRhgbqYi79ErVnSAvOIxoimhDu7+xX6tQkZYFDTBXNA9G4K+KTblHxRSC
Dg+7yRQVzUm784r204aTuGuZSNYe6mNlzvINe5sJWTDf2HE7JY+wHBnKN9rgC3zt
orEOZCfJcfoBhRbVsjmYHsX7L4Yvp/5A2LWwvW0LoQKBgQDOFm4jsl28QnCt+w88
X9hWGmEsdfdhy+rP300ciLy/L/2xGHMPbBiQQCuMBAatAvJVkET6ftfoMoXKxERv
wGPnc4gWtfySEdeZkPjg754HqtWQPFr0eKP3yivHges+Z8mwk6fIauE3CBJBAA5X
62zGh/PNY74Nlee+Edu9FgbXrQKBgQC7SJWjGI/h+UGZXK1k3WgTVwfcGfgceLV/
wmQTffT+WTsFEiAQNKm51VKRjAk4vxW6JkSo4bHZPjR0ZuK4Pze+/IpSn2nEHBg7
eg+hbCcmNkgJR7reidPbiPejtM6+mgugZiBkhKi/NWKF71GpZhiv7M6cWhSd2XSV
0I6+X1xkeQKBgQDJl0FXo8NzQx6L4Vju+uZYm2dQoXhCbsEbY9g/QDY5Yo1rbXon
rNp+SHcQeGO7W3WHYx9GVUuHs9wSE1jKY8yV+/o0FQKiM9fNPPVmup2/7EkJ1TA3
kcb6vQWEG77shYPSOS1Xq8zwEvIgKRjewcjejuBameWvzmIpF7j1xpUc5QKBgQCI
3Nllj+yN8g5rWdvpCxgkkgRPZ7b2b4wLqm5iBDlGqsTDxuQhk6q5AFjPvmt6ycHC
AHdKh2zl2lyQ+CMVDDXb30fia1bqlrFqvZ+wko3lkeOAzKeWO1jUZTq7qsUvavm2
JQvlCUEcQpIWWLbvuYmu/rpabkYEuMZHOVsnah7l2QKBgQCedSuSWUxLxmQQu2Ri
lfpts6F0SwVIO43UeE+bBVJArbHFZKXOb3HJ8CV9sgpfhYZPU+NqCnfvaZRyI2us
SSDk4Ki3CTdueA7HBr+zCHwXsxEYL1cElQvhbSiOeXEiJ4vbk0yfY0VC0WEn1yoc
UlqL1DcgX6Szi9w/p7B4BZO9iA==
-----END PRIVATE KEY-----
";

	fn tls_route(sni: &str, cert: &[u8], key: &[u8]) -> RouteSpec {
		RouteSpec {
			sni: sni.to_string(),
			metrics_group: String::new(),
			upstreams: Vec::new(),
			terminate_tls: true,
			cert_pem: Some(cert.to_vec()),
			key_pem: Some(key.to_vec()),
			mtls_ca_pem: None,
			require_client_cert: false,
			suspended: false,
			suspend_timeout_ms: 100,
			max_cps: None,
			burst: None,
			source_address_mode: SourceAddressMode::None,
			forward_fingerprint: ForwardFingerprint::None,
			http2: false,
			protocol: RouteProtocol::Opaque,
		}
	}

	// A single route with a mismatched cert/key must not abort the whole table: the
	// healthy co-tenant on the same listener stays routable, the bad one is dropped.
	#[test]
	fn bad_route_is_skipped_not_fatal() {
		let specs = vec![
			tls_route("good.example.com", CERT_A, KEY_A),
			tls_route("bad.example.com", CERT_A, KEY_B), // KeyMismatch
		];

		let table = build_route_table(&specs, &ListenerTlsSpec::empty(), None)
			.expect("a single bad route must not fail the whole build");

		assert!(
			table.resolve(Some("good.example.com")).is_some(),
			"the valid route must remain present"
		);
		assert!(
			table.resolve(Some("bad.example.com")).is_none(),
			"the unbuildable route must be absent (no default fallback)"
		);
	}

	// A dropped route must fail closed, not silently fall through to a broader wildcard: it was
	// configured for this SNI, just rejected — very different from "no route was ever set up
	// here." Without this, a rejected exact route shadowed by a wildcard would misroute that
	// tenant's traffic to the wildcard's (unrelated) upstream with no visible error.
	#[test]
	fn dropped_exact_route_does_not_fall_through_to_wildcard() {
		let specs = vec![
			tls_route("api.acme.com", CERT_A, KEY_B), // KeyMismatch — dropped, no last-good
			tls_route("*.acme.com", CERT_A, KEY_A),
		];

		let table = build_route_table(&specs, &ListenerTlsSpec::empty(), None).expect("build");

		assert!(
			table.resolve(Some("api.acme.com")).is_none(),
			"a dropped exact route must resolve to nothing, not the wildcard's upstream"
		);
		assert!(
			table.resolve(Some("other.acme.com")).is_some(),
			"an unrelated subdomain must still reach the (valid) wildcard route"
		);
	}

	// Same fail-closed requirement when the *wildcard* itself is the one that's dropped: a
	// matching subdomain must not fall through to the default route either.
	#[test]
	fn dropped_wildcard_route_does_not_fall_through_to_default() {
		let specs = vec![tls_route("*.acme.com", CERT_A, KEY_B)]; // KeyMismatch — dropped

		let table = build_route_table(&specs, &ListenerTlsSpec::empty(), None).expect("build");

		assert!(
			table.resolve(Some("api.acme.com")).is_none(),
			"a subdomain matching a dropped wildcard must resolve to nothing, not fall through to default"
		);
	}

	// The inverse and more dangerous case: a dropped wildcard must NOT shadow a healthy, more
	// specific exact route at the same suffix. A prior version of the fail-closed check tested
	// `dropped_wildcard` before `exact`, which black-holed every exact route under any wildcard
	// that happened to fail validation — turning one tenant's wildcard typo into an outage for
	// every co-tenant sharing that parent domain.
	#[test]
	fn healthy_exact_route_survives_a_dropped_sibling_wildcard() {
		let specs = vec![
			tls_route("*.acme.com", CERT_A, KEY_B),  // KeyMismatch — dropped
			tls_route("api.acme.com", CERT_A, KEY_A), // valid, more specific
		];

		let table = build_route_table(&specs, &ListenerTlsSpec::empty(), None).expect("build");

		assert!(
			table.resolve(Some("api.acme.com")).is_some(),
			"a healthy exact route must resolve normally even when a sibling wildcard at the same suffix was dropped"
		);
		assert!(
			table.resolve(Some("other.acme.com")).is_none(),
			"a subdomain with no exact route of its own must still fail closed against the dropped wildcard"
		);
	}

	// On a hot-swap, a route whose cert transiently fails to rebuild (the normal cert+key
	// non-atomic write window) must retain its last-good route from the live table rather
	// than dropping the SNI.
	#[test]
	fn transient_failure_retains_last_good_on_hot_swap() {
		// First build with a valid cert → the live table.
		let good = vec![tls_route("tenant.example.com", CERT_A, KEY_A)];
		let live = build_route_table(&good, &ListenerTlsSpec::empty(), None).expect("initial build");
		let live_route = live.resolve(Some("tenant.example.com")).expect("live route");
		let live_identity = live_route.metric_identity.clone();

		// Hot-swap where the same SNI now presents a mismatched pair (mid-rotation).
		let mismatched = vec![tls_route("tenant.example.com", CERT_A, KEY_B)];
		let swapped = build_route_table(&mismatched, &ListenerTlsSpec::empty(), Some(&live))
			.expect("hot-swap must not fail");
		assert!(
			swapped.resolve(Some("tenant.example.com")).is_some(),
			"the SNI must keep its last-good route across a transient rebuild failure"
		);
		assert!(Arc::ptr_eq(
			&swapped.resolve(Some("tenant.example.com")).unwrap().metric_identity,
			&live_identity
		));
		assert!(
			swapped.failing_snis.contains("tenant.example.com"),
			"the transiently-failing SNI must be tracked so it isn't re-logged every reconcile"
		);

		// With no previous table (initial build), the same bad route is dropped.
		let fresh = build_route_table(&mismatched, &ListenerTlsSpec::empty(), None).expect("build");
		assert!(
			fresh.resolve(Some("tenant.example.com")).is_none(),
			"with no prior route there is nothing to retain — the SNI is dropped"
		);
	}

	#[test]
	fn route_metric_identity_survives_reload_until_group_changes() {
		let mut initial = tls_route("tenant.example.com", CERT_A, KEY_A);
		initial.metrics_group = "tenant-1".to_string();
		let live = build_route_table(&[initial.clone()], &ListenerTlsSpec::empty(), None).expect("initial build");
		let live_identity = live.resolve(Some("tenant.example.com")).unwrap().metric_identity.clone();

		let reloaded = build_route_table(&[initial.clone()], &ListenerTlsSpec::empty(), Some(&live)).expect("reload");
		assert!(Arc::ptr_eq(
			&reloaded.resolve(Some("tenant.example.com")).unwrap().metric_identity,
			&live_identity
		));

		initial.metrics_group = "tenant-2".to_string();
		let regrouped = build_route_table(&[initial], &ListenerTlsSpec::empty(), Some(&reloaded)).expect("regroup");
		assert!(!Arc::ptr_eq(
			&regrouped.resolve(Some("tenant.example.com")).unwrap().metric_identity,
			&live_identity
		));
	}

	// Unlike a cert-build failure (a transient race that heals on the next reconcile), a
	// protocol-declaration/no-carrier rejection is a permanent config error — it never heals
	// without a human editing the config. It must therefore never get cert-style last-good
	// carry-forward: an operator who accidentally drops `protocol: 'http'` in the same edit that
	// repoints a route to a new upstream must see that route stop serving, not have `updateConfig`
	// silently keep the old route (old upstream included) running indefinitely.
	#[test]
	fn permanent_protocol_rejection_never_carries_forward_on_hot_swap() {
		let mut good = tls_route("tenant.example.com", CERT_A, KEY_A);
		good.source_address_mode = SourceAddressMode::XForwardedFor;
		good.protocol = RouteProtocol::Http;
		let live = build_route_table(&[good], &ListenerTlsSpec::empty(), None).expect("initial build");
		assert!(live.resolve(Some("tenant.example.com")).is_some());

		// Hot-swap drops the protocol declaration — a permanent rejection, not a transient one.
		let mut broken = tls_route("tenant.example.com", CERT_A, KEY_A);
		broken.source_address_mode = SourceAddressMode::XForwardedFor;
		// protocol left at its default (Opaque) — undeclared.
		let swapped = build_route_table(&[broken], &ListenerTlsSpec::empty(), Some(&live)).expect("hot-swap must not fail");
		assert!(
			swapped.resolve(Some("tenant.example.com")).is_none(),
			"a permanent protocol-declaration rejection must drop the route, not silently carry the previous one forward"
		);
	}

	#[test]
	fn header_injection_detection() {
		// xForwardedFor always needs protocol: 'http', regardless of fingerprint.
		assert!(requires_http_protocol(SourceAddressMode::XForwardedFor, ForwardFingerprint::None));
		// A header-carried fingerprint (any mode other than proxyProtocolV2) needs it too.
		assert!(requires_http_protocol(SourceAddressMode::None, ForwardFingerprint::Ja3));
		assert!(requires_http_protocol(SourceAddressMode::ProxyProtocol, ForwardFingerprint::Ja4));
		// proxyProtocolV2 carries the fingerprint as a TLV — never needs the declaration.
		assert!(!requires_http_protocol(SourceAddressMode::ProxyProtocolV2, ForwardFingerprint::Ja3));
		// No header-injection mode requested at all.
		assert!(!requires_http_protocol(SourceAddressMode::None, ForwardFingerprint::None));
		assert!(!requires_http_protocol(SourceAddressMode::ProxyProtocol, ForwardFingerprint::None));
	}
}
