use crate::balancer::{UdsBalancer, UdsSlotSpec};
use crate::failover::{Failover, FailoverRoute, FailoverSpec};
use crate::metrics::RouteMetrics;
use crate::tls::{sha256, CertSpec, MtlsSpec, TlsConfigCache};
use arc_swap::ArcSwap;
use ipnetwork::{IpNetwork, Ipv4Network};
use rustls::ServerConfig;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;

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
			if self
				.tokens
				.compare_exchange(old, new, Ordering::Relaxed, Ordering::Relaxed)
				.is_ok()
			{
				let _ = self.last_refill_ns.compare_exchange(
					last,
					now,
					Ordering::Relaxed,
					Ordering::Relaxed,
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
			if self
				.tokens
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

/// Which client TLS fingerprints (none, either, or both) symphony forwards to the upstream so
/// the backend can act on them itself. Every selected kind rides the same carrier, chosen by
/// `SourceAddressMode`: a PROXY v2 TLV under `ProxyProtocolV2`, otherwise an injected
/// `X-JA3`/`X-JA4` HTTP header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ForwardFingerprint {
	pub ja3: bool,
	pub ja4: bool,
}

impl ForwardFingerprint {
	pub const NONE: Self = Self {
		ja3: false,
		ja4: false,
	};

	pub fn is_empty(self) -> bool {
		!self.ja3 && !self.ja4
	}
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
		|| (!fingerprint.is_empty() && mode != SourceAddressMode::ProxyProtocolV2)
}

// ── Route source allowlist ────────────────────────────────────────────────────

/// A route's `allowedSources`: the only TCP peers admitted to it. Unrelated to the listener-level
/// `protection.allowlist`, which exempts peers from protection checks rather than restricting them.
#[derive(Clone, Debug)]
pub struct SourceAllowlist(Arc<[IpNetwork]>);

impl SourceAllowlist {
	pub fn parse(entries: &[String]) -> Result<Option<Self>, String> {
		if entries.is_empty() {
			return Ok(None);
		}
		Self::parse_required(entries, "allowedSources").map(Some)
	}

	/// For a list whose absence must not mean "anyone": an empty list permits nobody.
	pub fn parse_required(entries: &[String], label: &str) -> Result<Self, String> {
		let networks = entries
			.iter()
			.map(|entry| parse_source_network(entry, label))
			.collect::<Result<Vec<_>, _>>()?;
		Ok(Self(networks.into()))
	}

	/// A dual-stack listener reports an IPv4 client as `::ffff:a.b.c.d`; it is matched as IPv4,
	/// so IPv6 entries never admit it.
	pub fn permits(&self, peer: IpAddr) -> bool {
		let peer = peer.to_canonical();
		self.0.iter().any(|network| network.contains(peer))
	}
}

/// An IPv4-mapped IPv6 CIDR is stored as its IPv4 form: peers are canonicalised to IPv4 before
/// matching, so the mapped form would otherwise never match anything. One with a prefix under 96
/// (`::ffff:10.0.0.0/8`, an IPv4 length on the mapped form) would instead be a v6 network around
/// `::`, so it is rejected.
pub(crate) fn parse_source_network(entry: &str, label: &str) -> Result<IpNetwork, String> {
	let invalid =
		|reason: &dyn std::fmt::Display| format!("invalid {label} CIDR '{entry}': {reason}");
	let network: IpNetwork = entry.parse().map_err(|e| invalid(&e))?;
	if let IpNetwork::V6(v6) = network {
		if let Some(v4) = v6.ip().to_ipv4_mapped() {
			let prefix = v6.prefix().checked_sub(96).ok_or_else(|| {
				invalid(&"an IPv4-mapped CIDR needs a prefix of at least 96 (or write it as IPv4)")
			})?;
			return Ipv4Network::new(v4, prefix)
				.map(IpNetwork::V4)
				.map_err(|e| invalid(&e));
		}
	}
	Ok(network)
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
	pub allowed_sources: Option<SourceAllowlist>,
	pub failover: Option<Arc<Failover>>,
}

pub struct RouteMetricIdentity {
	pub route: Arc<str>,
	pub group: Arc<str>,
	pub counters: Arc<RouteMetrics>,
}

impl RouteMetricIdentity {
	fn new(route: &str, group: &str) -> Self {
		Self {
			route: Arc::from(route),
			group: Arc::from(group),
			counters: Arc::new(RouteMetrics::default()),
		}
	}
}

// ── Route table ───────────────────────────────────────────────────────────────

/// True when `sni` matches exactly one left-most label against `suffix` (a wildcard's stored
/// suffix, without the `*.` prefix) — e.g. "foo.example.com" matches suffix "example.com" but
/// "a.b.example.com" does not.
/// Compares bytes: a client SNI may be any UTF-8, and a `&str` slice off a char boundary panics.
fn wildcard_suffix_matches(sni: &str, suffix: &str) -> bool {
	let (sni, suffix) = (sni.as_bytes(), suffix.as_bytes());
	if sni.len() <= suffix.len() + 1 {
		return false;
	}
	let dot_pos = sni.len() - suffix.len() - 1;
	sni[dot_pos] == b'.' && &sni[dot_pos + 1..] == suffix && !sni[..dot_pos].contains(&b'.')
}

pub struct RouteTable {
	exact: HashMap<Arc<str>, Route>,
	/// (suffix_without_star_dot, route) — "*.example.com" stored as "example.com"
	wildcard: Vec<(Arc<str>, Route)>,
	default: Option<Route>,
	/// Stable configured-route order, prepared when the table is built rather than on every scrape.
	metric_identities: Vec<Arc<RouteMetricIdentity>>,
	/// All UdsBalancers that have at least one pid/tid-configured slot.
	/// Used by the CPU monitor task spawned in `proxy.rs::start()`.
	pub monitored_balancers: Vec<Arc<UdsBalancer>>,
	/// All UdsBalancers with IP affinity, for `evict_affinity_periodically`.
	affinity_balancers: Vec<Arc<UdsBalancer>>,
	/// SNIs whose cert failed to build in this table. Carried across a hot-swap so a
	/// persistently-broken route is logged only on the good→bad transition, not every reconcile.
	failing_snis: HashSet<Arc<str>>,
	/// SNIs served without failover because their `failover` policy is invalid. Separate from
	/// `failing_snis` so one failure's log-once state cannot silence the other's.
	invalid_failover: HashSet<Arc<str>>,
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
	/// The client-certificate policy each installed route enforces, keyed by configured SNI
	/// (`*.`-prefixed for a wildcard). Kept here rather than on `Route`, which every connection
	/// clones into its task.
	client_auth: HashMap<Arc<str>, ClientAuth>,
	/// Routes with `failover`, for the recovery probe and the metrics export.
	failover_routes: Vec<FailoverRoute>,
}

impl RouteTable {
	/// Number of routes serving traffic, including the default route if one is configured.
	pub fn route_count(&self) -> usize {
		self.exact.len() + self.wildcard.len() + usize::from(self.default.is_some())
	}

	/// Number of SNIs rejected in this table — dropped, serving a carried-forward last-good cert, or
	/// serving without an invalid `failover` policy. Non-zero means a config needs attention.
	pub fn failing_route_count(&self) -> usize {
		self.failing_snis.union(&self.invalid_failover).count()
	}

	pub fn metric_identities(&self) -> &[Arc<RouteMetricIdentity>] {
		&self.metric_identities
	}

	pub fn failover_routes(&self) -> &[FailoverRoute] {
		&self.failover_routes
	}

	#[cfg(test)]
	pub fn resolve(&self, sni: Option<&str>) -> Option<&Route> {
		self.resolve_with(sni, true)
	}

	/// `allow_default: false` is for lookups where only a route configured for the name may answer:
	/// the failover ingress (a peer that does not serve this name must close before the handshake
	/// so the forwarding node tries another peer) and the ACME http-01 proxy.
	pub fn resolve_with(&self, sni: Option<&str>, allow_default: bool) -> Option<&Route> {
		let default = || {
			if allow_default {
				self.default.as_ref()
			} else {
				None
			}
		};
		let Some(sni) = sni else {
			return default();
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
		if self
			.dropped_wildcard
			.iter()
			.any(|suffix| wildcard_suffix_matches(sni, suffix))
		{
			return None;
		}

		default()
	}

	/// Look up the route stored under the key a spec's SNI would insert to (the exact SNI,
	/// or the suffix of a `*.` wildcard) — not the resolve()-style match. Used to carry a
	/// last-good route forward across a hot-swap when the new cert transiently fails to build.
	fn get_for_spec_sni(&self, sni: &str) -> Option<&Route> {
		if let Some(suffix) = sni.strip_prefix("*.") {
			self.wildcard
				.iter()
				.find(|(s, _)| s.as_ref() == suffix)
				.map(|(_, r)| r)
		} else if sni.is_empty() {
			self.default.as_ref()
		} else {
			self.exact.get(sni)
		}
	}
}

// ── Builder / config types ────────────────────────────────────────────────────

/// Raw JS-provided upstream specification.
#[derive(Clone, Debug)]
pub enum UpstreamSpec {
	Tcp {
		host: String,
		port: u16,
	},
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
	/// Unparsed: an invalid entry drops this route in `build_route_table` instead of failing the
	/// whole config.
	pub allowed_sources: Vec<String>,
	/// Unvalidated: an invalid policy serves the route without failover rather than failing the
	/// whole config.
	pub failover: Option<FailoverSpec>,
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

fn effective_mtls<'a>(
	spec: &'a RouteSpec,
	listener_tls: &'a ListenerTlsSpec,
) -> Option<(&'a [u8], bool)> {
	match spec.mtls_ca_pem.as_deref() {
		Some(ca) => Some((ca, spec.require_client_cert)),
		None => listener_tls
			.mtls_ca_pem
			.as_deref()
			.map(|ca| (ca, listener_tls.require_client_cert)),
	}
}

/// The client-certificate policy a route spec asks for, as `build_route` would enforce it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientAuth {
	/// symphony never terminates, so any client authentication is the upstream's own. Distinct
	/// from `NoClientCert`: a terminating route must not stand in for a passthrough whose upstream
	/// requires client certificates.
	Passthrough,
	NoClientCert,
	ClientCert {
		ca_sha256: [u8; 32],
		required: bool,
	},
}

impl ClientAuth {
	fn of(spec: &RouteSpec, listener_tls: &ListenerTlsSpec) -> Self {
		if !spec.terminate_tls {
			return Self::Passthrough;
		}
		match effective_mtls(spec, listener_tls) {
			None => Self::NoClientCert,
			Some((ca, required)) => Self::ClientCert {
				ca_sha256: sha256(ca),
				required,
			},
		}
	}
}

fn tombstone(
	sni: &str,
	dropped_exact: &mut HashSet<Arc<str>>,
	dropped_wildcard: &mut Vec<Arc<str>>,
) {
	if let Some(suffix) = sni.strip_prefix("*.") {
		dropped_wildcard.push(Arc::from(suffix));
	} else {
		dropped_exact.insert(Arc::from(sni));
	}
}

/// Build a RouteTable from a list of route specs and a listener-level fallback.
///
/// `previous` is the currently-live table on a hot-swap (None on initial construction). When
/// a route's cert fails to build, its last-good route is carried forward from `previous` if
/// present and it enforces the client-certificate policy the new spec asks for, so a transient
/// rotation mismatch keeps serving the old (still-valid) cert instead of dropping the SNI. A
/// route whose requested policy changed is dropped instead: its old verifier would otherwise
/// outlive the edit that replaced it.
///
/// `cache` is the proxy's long-lived `TlsConfigCache`, deliberately *not* created here: an
/// unchanged cert must map to the same `Arc<ServerConfig>` across rebuilds so its TLS session
/// state survives the reload. Sweeping it (`retain_used`) is the *caller's* job, once it commits
/// the returned table — this table is only one half of an all-or-nothing `updateConfig`, and
/// retiring configs for a table that never goes live would strand the running table's sessions.
/// The `clear_used` below is not that sweep: it drops only configs nothing references yet, i.e.
/// the previous build's, if that update was abandoned.
pub fn build_route_table(
	specs: &[RouteSpec],
	listener_tls: &ListenerTlsSpec,
	previous: Option<&RouteTable>,
	cache: &mut TlsConfigCache,
) -> crate::error::Result<RouteTable> {
	cache.clear_used();
	let mut exact: HashMap<Arc<str>, Route> = HashMap::new();
	let mut wildcard: Vec<(Arc<str>, Route)> = Vec::new();
	let mut monitored_balancers: Vec<Arc<UdsBalancer>> = Vec::new();
	let mut affinity_balancers: Vec<Arc<UdsBalancer>> = Vec::new();
	let mut failing_snis: HashSet<Arc<str>> = HashSet::new();
	let mut invalid_failover: HashSet<Arc<str>> = HashSet::new();
	let mut configured_wildcards = HashSet::with_capacity(specs.len());
	let mut dropped_exact: HashSet<Arc<str>> = HashSet::new();
	let mut dropped_wildcard: Vec<Arc<str>> = Vec::new();
	let mut client_auth: HashMap<Arc<str>, ClientAuth> = HashMap::new();
	let mut failover_routes: Vec<FailoverRoute> = Vec::new();
	let mut default: Option<Route> = None;
	let last_exact: HashMap<&str, usize> = specs
		.iter()
		.enumerate()
		.filter(|(_, spec)| !spec.sni.starts_with("*."))
		.map(|(i, spec)| (spec.sni.as_str(), i))
		.collect();

	for (i, spec) in specs.iter().enumerate() {
		// One spec decides each configured SNI, even when it is rejected: otherwise a duplicate could
		// serve the SNI under a policy the deciding spec didn't ask for. Exact duplicates collapse
		// last-wins. Wildcards live in a Vec and resolve first-wins, so later duplicates are isolated,
		// which also keeps the metric table from exposing two identical configured route labels.
		if last_exact
			.get(spec.sni.as_str())
			.is_some_and(|&last| last != i)
		{
			continue;
		}
		let wildcard_suffix = spec.sni.strip_prefix("*.");
		if wildcard_suffix.is_some_and(|suffix| !configured_wildcards.insert(suffix)) {
			let newly_failing =
				previous.is_none_or(|p| !p.failing_snis.contains(spec.sni.as_str()));
			failing_snis.insert(Arc::from(spec.sni.as_str()));
			if newly_failing {
				eprintln!(
					"symphony: skipping duplicate route '{}': duplicate SNI",
					spec.sni
				);
			}
			continue;
		}

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
			let newly_failing =
				previous.is_none_or(|p| !p.failing_snis.contains(spec.sni.as_str()));
			failing_snis.insert(Arc::from(spec.sni.as_str()));
			if newly_failing {
				eprintln!("symphony: skipping route '{}': {}", spec.sni, e);
			}
			tombstone(&spec.sni, &mut dropped_exact, &mut dropped_wildcard);
			continue;
		}

		// A permanent config error, like the protocol declaration: tombstoned, never carried forward.
		// Logged also when an already-failing SNI was serving a carried-forward route, since this
		// is the reconcile that takes it offline.
		let allowed_sources = match SourceAllowlist::parse(&spec.allowed_sources) {
			Ok(allowed_sources) => allowed_sources,
			Err(e) => {
				let newly_failing =
					previous.is_none_or(|p| !p.failing_snis.contains(spec.sni.as_str()));
				let was_serving = previous.is_some_and(|p| p.get_for_spec_sni(&spec.sni).is_some());
				failing_snis.insert(Arc::from(spec.sni.as_str()));
				if newly_failing || was_serving {
					eprintln!("symphony: skipping route '{}': {}", spec.sni, e);
				}
				tombstone(&spec.sni, &mut dropped_exact, &mut dropped_wildcard);
				continue;
			}
		};

		let previous_route = previous.and_then(|p| p.get_for_spec_sni(&spec.sni));
		// Failover adds availability; a broken policy must not remove the route itself.
		// A peer's failover ingress never serves its default route, so every peer would refuse it.
		let failover_policy = match spec.failover.as_ref().map(|f| {
			if spec.sni.is_empty() {
				Err("failover is not supported on the default route".to_string())
			} else {
				f.parse()
			}
		}) {
			None => None,
			Some(Ok(policy)) => Some(policy),
			Some(Err(e)) => {
				let newly_failing =
					previous.is_none_or(|p| !p.invalid_failover.contains(spec.sni.as_str()));
				invalid_failover.insert(Arc::from(spec.sni.as_str()));
				if newly_failing {
					eprintln!(
						"symphony: route '{}': {e}; serving it without failover",
						spec.sni
					);
				}
				None
			}
		};

		let requested_auth = ClientAuth::of(spec, listener_tls);

		// Isolate per-route failures: a single route whose cert can't be built (e.g. a
		// rotated key no longer matching an inlined chain → rustls KeyMismatch) must not
		// abort the whole table and take every other tenant on the port down with it.
		let inherit = Inherit {
			previous: previous_route,
			track_health: failover_policy.is_some(),
		};
		let mut carried = false;
		let mut route = match build_route(spec, listener_tls, cache, inherit) {
			Ok(route) => route,
			Err(e) => {
				// Log only on the good→bad transition: a persistently-broken cert would
				// otherwise re-log on every reconcile, since each cert-file event rebuilds
				// the whole table.
				let newly_failing =
					previous.is_none_or(|p| !p.failing_snis.contains(spec.sni.as_str()));
				failing_snis.insert(Arc::from(spec.sni.as_str()));

				let last_good = previous.and_then(|p| {
					let route = p.get_for_spec_sni(&spec.sni)?;
					Some((
						route,
						p.client_auth.get(spec.sni.as_str()) == Some(&requested_auth),
					))
				});
				match last_good {
					// On a hot-swap, a cert and key rotate as two non-atomic files, so a
					// transient mismatch mid-rotation is normal. Carry the previous route
					// forward *whole* (cert and upstreams) — intentional: its cert is still
					// valid, and the route heals on the next reconcile when the pair is
					// consistent. If the route's upstreams also changed in the same reconcile,
					// they too persist until then; that's the accepted cost of last-good.
					Some((prev, true)) => {
						if newly_failing {
							eprintln!(
								"symphony: route '{}' failed to rebuild ({}); retaining last-good route",
								spec.sni, e
							);
						}
						carried = true;
						prev.clone()
					}
					// The previous route's `tls_config` holds its client verifier, so retaining it
					// would keep enforcing the old policy. Always logged: the previous table was
					// serving this SNI, so this is a transition even if it was already failing.
					Some((_, false)) => {
						eprintln!(
							"symphony: skipping route '{}': {}; its last-good route enforces a different client-certificate policy, so it is not retained",
							spec.sni, e
						);
						tombstone(&spec.sni, &mut dropped_exact, &mut dropped_wildcard);
						continue;
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
						tombstone(&spec.sni, &mut dropped_exact, &mut dropped_wildcard);
						continue;
					}
				}
			}
		};

		// After the carry-forward branch, so a retained last-good route enforces the new list.
		route.allowed_sources = allowed_sources;

		// A route's UDS slots track health exactly when it has failover, since only the failover
		// probe clears a tracked slot. A carried-forward route keeps its own slots, re-created with
		// tracking switched when the policy's presence changed.
		if carried && !tracks_health_as(&route, failover_policy.is_some()) {
			let track = failover_policy.is_some();
			route.destination = retracked(&route.destination, track);
			route.destination_h2 = route
				.destination_h2
				.as_ref()
				.map(|dest| retracked(dest, track));
		}

		// Reusing by the full metric identity keeps ordinary cert/upstream reloads continuous
		// without moving historical counters when a route changes tenant groups.
		if let Some(previous_route) = previous_route {
			if previous_route.metric_identity.group.as_ref() == spec.metrics_group {
				route.metric_identity = previous_route.metric_identity.clone();
			}
		}

		// After the carry-forward branch, like `allowed_sources`: a retained last-good route takes
		// the new policy, so a reload that sets `drain` during a cert rotation still drains.
		route.failover = failover_policy.map(|policy| {
			let previous_failover = previous_route
				.filter(|p| Arc::ptr_eq(&p.metric_identity, &route.metric_identity))
				.and_then(|p| p.failover.as_deref());
			let tcp_health = match &route.destination {
				Destination::Tcp(addr) => Some(
					previous_route
						.and_then(|p| match (&p.destination, &p.failover) {
							(Destination::Tcp(prev), Some(f)) if prev == addr => {
								f.tcp_health.clone()
							}
							_ => None,
						})
						.unwrap_or_default(),
				),
				Destination::UdsSet(_) => None,
			};
			Arc::new(Failover::new(policy, previous_failover, tcp_health))
		});
		if let Some(failover) = &route.failover {
			failover_routes.push(FailoverRoute {
				identity: route.metric_identity.clone(),
				failover: failover.clone(),
				destination: route.destination.clone(),
				destination_h2: route.destination_h2.clone(),
			});
		}
		// Collected from the route actually installed, which may be a carried-forward one.
		for dest in std::iter::once(&route.destination).chain(route.destination_h2.iter()) {
			if let Destination::UdsSet(ref bal) = dest {
				if bal.has_monitored_slots() {
					monitored_balancers.push(bal.clone());
				}
				if bal.has_affinity() {
					affinity_balancers.push(bal.clone());
				}
			}
		}

		client_auth.insert(Arc::from(spec.sni.as_str()), requested_auth);
		if spec.sni.starts_with("*.") {
			let suffix: Arc<str> = Arc::from(&spec.sni[2..]);
			wildcard.push((suffix, route));
		} else if spec.sni.is_empty() {
			default = Some(route);
		} else {
			let key: Arc<str> = Arc::from(spec.sni.as_str());
			exact.insert(key, route);
		}
	}

	let mut metric_identities: Vec<_> = exact
		.values()
		.chain(wildcard.iter().map(|(_, route)| route))
		.chain(default.iter())
		.map(|route| route.metric_identity.clone())
		.collect();
	metric_identities
		.sort_unstable_by(|a, b| a.route.cmp(&b.route).then_with(|| a.group.cmp(&b.group)));

	Ok(RouteTable {
		exact,
		wildcard,
		default,
		metric_identities,
		monitored_balancers,
		affinity_balancers,
		failing_snis,
		invalid_failover,
		dropped_exact,
		dropped_wildcard,
		client_auth,
		failover_routes,
	})
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

fn retracked(dest: &Destination, track: bool) -> Destination {
	match dest {
		Destination::UdsSet(balancer) => Destination::UdsSet(Arc::new(balancer.retracked(track))),
		Destination::Tcp(addr) => Destination::Tcp(*addr),
	}
}

fn tracks_health_as(route: &Route, tracked: bool) -> bool {
	std::iter::once(&route.destination)
		.chain(route.destination_h2.iter())
		.all(|dest| match dest {
			Destination::UdsSet(balancer) => balancer.tracked_slots().next().is_some() == tracked,
			Destination::Tcp(_) => true,
		})
}

/// What a route's balancers carry over from the route they replace: CPU sampling always, slot
/// health when the route has failover.
#[derive(Clone, Copy)]
struct Inherit<'a> {
	previous: Option<&'a Route>,
	track_health: bool,
}

fn build_route(
	spec: &RouteSpec,
	listener_tls: &ListenerTlsSpec,
	cache: &mut TlsConfigCache,
	inherit: Inherit,
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

		let mtls_spec =
			effective_mtls(spec, listener_tls).map(|(ca, require_client_cert)| MtlsSpec {
				client_ca_pem: ca.to_vec(),
				require_client_cert,
			});

		Some(cache.get_or_build(&cert_spec, mtls_spec.as_ref(), spec.http2)?)
	} else {
		None
	};

	let (destination, destination_h2) = build_destinations(spec, inherit)?;

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
		allowed_sources: None,
		failover: None,
	})
}

/// Build the route's destinations: the default (h1) destination plus, when any
/// upstream is marked `protocol: "h2"`, a separate destination for connections
/// that negotiated h2 in ALPN.
fn build_destinations(
	spec: &RouteSpec,
	inherit: Inherit,
) -> crate::error::Result<(Destination, Option<Destination>)> {
	// Suspended routes or routes with no upstreams use a placeholder TCP dest
	// that is replaced by resolveConnection() before any data flows.
	if spec.suspended || spec.upstreams.is_empty() {
		return Ok((Destination::Tcp("127.0.0.1:1".parse().unwrap()), None));
	}

	let is_h2 =
		|u: &UpstreamSpec| matches!(u, UpstreamSpec::Uds { protocol: Some(p), .. } if p == "h2");
	let h1_specs: Vec<&UpstreamSpec> = spec.upstreams.iter().filter(|u| !is_h2(u)).collect();
	let h2_specs: Vec<&UpstreamSpec> = spec.upstreams.iter().filter(|u| is_h2(u)).collect();

	if h1_specs.is_empty() {
		return Err(crate::error::SymphonyError::Config(format!(
			"route '{}': all upstreams are marked protocol 'h2' — at least one default (http/1.x) upstream is required for clients that do not negotiate h2",
			spec.sni
		)));
	}

	let previous_balancer =
		|pick: fn(&Route) -> Option<&Destination>| match inherit.previous.and_then(pick) {
			Some(Destination::UdsSet(balancer)) => Some(balancer.as_ref()),
			_ => None,
		};
	let destination = build_destination_for(
		&h1_specs,
		previous_balancer(|r| Some(&r.destination)),
		inherit.track_health,
	)?;
	let destination_h2 = if h2_specs.is_empty() {
		None
	} else {
		Some(build_destination_for(
			&h2_specs,
			previous_balancer(|r| r.destination_h2.as_ref()),
			inherit.track_health,
		)?)
	};
	Ok((destination, destination_h2))
}

fn build_destination_for(
	upstreams: &[&UpstreamSpec],
	previous: Option<&UdsBalancer>,
	track_health: bool,
) -> crate::error::Result<Destination> {
	let first = upstreams
		.first()
		.ok_or_else(|| crate::error::SymphonyError::Config("route has no upstreams".to_string()))?;
	match first {
		UpstreamSpec::Tcp { host, port } => {
			let addr: SocketAddr = format!("{host}:{port}")
				.parse()
				.map_err(crate::error::SymphonyError::AddrParse)?;
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
			let balancer =
				UdsBalancer::new(slots, ip_affinity, affinity_ttl_ms).with_cpu_from(previous);
			Ok(Destination::UdsSet(Arc::new(if track_health {
				balancer.with_health(previous)
			} else {
				balancer
			})))
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

/// `pick()` ignores an expired affinity entry but only overwrites it when that same IP returns, so
/// without this the maps grow with every distinct client IP until a reload.
///
/// `DashMap::retain` is O(N) and write-locks each shard while scanning it, so it runs on the
/// blocking pool, as IP-state eviction does; a `pick()` hashing to the shard under scan still
/// waits for that one shard.
pub async fn evict_affinity_periodically(
	live: Arc<LiveRouteTable>,
	interval: Duration,
	mut shutdown: broadcast::Receiver<()>,
) {
	loop {
		tokio::select! {
			_ = shutdown.recv() => break,
			_ = tokio::time::sleep(interval) => {
				let table = live.0.load_full();
				if table.affinity_balancers.is_empty() {
					continue;
				}
				let _ = tokio::task::spawn_blocking(move || {
					for balancer in &table.affinity_balancers {
						balancer.evict_affinity();
					}
				})
				.await;
			}
		}
	}
}

#[cfg(test)]
pub(crate) mod tests {
	use super::*;

	// A self-signed cert (CERT_A) and its matching key (KEY_A), plus an unrelated key
	// (KEY_B). Pairing CERT_A with KEY_B reproduces the production rustls KeyMismatch a
	// cert rotation causes (leaf pubkey ≠ private key).
	pub(crate) const CERT_A: &[u8] = b"-----BEGIN CERTIFICATE-----
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

	pub(crate) const KEY_A: &[u8] = b"-----BEGIN PRIVATE KEY-----
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

	pub(crate) const KEY_B: &[u8] = b"-----BEGIN PRIVATE KEY-----
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

	pub(crate) fn tls_route(sni: &str, cert: &[u8], key: &[u8]) -> RouteSpec {
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
			forward_fingerprint: ForwardFingerprint::NONE,
			http2: false,
			protocol: RouteProtocol::Opaque,
			allowed_sources: Vec::new(),
			failover: None,
		}
	}

	fn config_ptr(table: &RouteTable, sni: &str) -> *const ServerConfig {
		Arc::as_ptr(
			table
				.resolve(Some(sni))
				.expect("route present")
				.tls_config
				.as_ref()
				.unwrap(),
		)
	}

	// A rebuild must hand an unchanged cert back the *same* ServerConfig. Identity is the whole
	// point: the TLS session cache and ticket keys live on that allocation, so a fresh one
	// silently invalidates every ticket already issued to clients.
	#[test]
	fn unchanged_cert_keeps_its_server_config_across_rebuilds() {
		let specs = vec![tls_route("tenant.example.com", CERT_A, KEY_A)];
		let mut cache = TlsConfigCache::new();

		let first = build_route_table(&specs, &ListenerTlsSpec::empty(), None, &mut cache)
			.expect("initial build");
		cache.retain_used();
		let second = build_route_table(&specs, &ListenerTlsSpec::empty(), Some(&first), &mut cache)
			.expect("rebuild");
		cache.retain_used();

		assert_eq!(
			config_ptr(&first, "tenant.example.com"),
			config_ptr(&second, "tenant.example.com"),
			"an unchanged cert must reuse its ServerConfig, or resumption dies on every reload"
		);

		// Control: a cache that does not outlive the build is exactly the bug — a new allocation.
		let detached = build_route_table(
			&specs,
			&ListenerTlsSpec::empty(),
			None,
			&mut TlsConfigCache::new(),
		)
		.expect("build with a fresh cache");
		assert_ne!(
			config_ptr(&first, "tenant.example.com"),
			config_ptr(&detached, "tenant.example.com"),
			"a per-build cache mints a new config — the behaviour the shared cache exists to avoid"
		);
	}

	// Retention is scoped to what the committed table actually references, so a cert that
	// rotates out is not held for the life of the process.
	#[test]
	fn sweep_retires_configs_no_route_references() {
		let mut cache = TlsConfigCache::new();
		let specs = vec![tls_route("tenant.example.com", CERT_A, KEY_A)];

		build_route_table(&specs, &ListenerTlsSpec::empty(), None, &mut cache).expect("build");
		cache.retain_used();
		assert_eq!(cache.len(), 1);

		// The route goes away; nothing asks for its config, so the sweep drops it.
		build_route_table(&[], &ListenerTlsSpec::empty(), None, &mut cache).expect("empty build");
		cache.retain_used();
		assert!(
			cache.is_empty(),
			"a config no live route references must not be retained"
		);
	}

	#[test]
	fn aborted_build_marks_do_not_retain_configs() {
		let mut cache = TlsConfigCache::new();
		let old = vec![tls_route("tenant.example.com", CERT_A, KEY_A)];
		let mut rotated_route = tls_route("tenant.example.com", CERT_A, KEY_A);
		rotated_route.http2 = true;
		let rotated = vec![rotated_route];

		let live = build_route_table(&old, &ListenerTlsSpec::empty(), None, &mut cache)
			.expect("initial build");
		cache.retain_used();

		// Simulate a route table whose later configuration validation aborts the update.
		drop(
			build_route_table(&rotated, &ListenerTlsSpec::empty(), Some(&live), &mut cache)
				.expect("aborted build"),
		);
		drop(
			build_route_table(&old, &ListenerTlsSpec::empty(), Some(&live), &mut cache)
				.expect("second aborted build"),
		);
		assert_eq!(
			cache.len(),
			1,
			"starting another build must discard the first aborted config"
		);
		let replacement =
			build_route_table(&old, &ListenerTlsSpec::empty(), Some(&live), &mut cache)
				.expect("replacement build");
		cache.retain_used();

		assert_eq!(
			cache.len(),
			1,
			"the aborted build's config must not survive the next committed sweep"
		);
		drop(replacement);
	}

	#[test]
	fn carried_forward_config_survives_sweep() {
		let mut cache = TlsConfigCache::new();
		let good = vec![tls_route("tenant.example.com", CERT_A, KEY_A)];
		let mismatch = vec![tls_route("tenant.example.com", CERT_A, KEY_B)];

		let live = build_route_table(&good, &ListenerTlsSpec::empty(), None, &mut cache)
			.expect("initial build");
		cache.retain_used();
		let expected = config_ptr(&live, "tenant.example.com");

		let carried = build_route_table(
			&mismatch,
			&ListenerTlsSpec::empty(),
			Some(&live),
			&mut cache,
		)
		.expect("carry forward");
		cache.retain_used();
		assert_eq!(
			cache.len(),
			1,
			"the carried-forward config is still serving traffic"
		);

		let healed =
			build_route_table(&good, &ListenerTlsSpec::empty(), Some(&carried), &mut cache)
				.expect("healed build");
		cache.retain_used();
		assert_eq!(
			expected,
			config_ptr(&healed, "tenant.example.com"),
			"healing a transient mismatch must preserve the original ticket keys"
		);
	}

	// A single route with a mismatched cert/key must not abort the whole table: the
	// healthy co-tenant on the same listener stays routable, the bad one is dropped.
	#[test]
	fn bad_route_is_skipped_not_fatal() {
		let specs = vec![
			tls_route("good.example.com", CERT_A, KEY_A),
			tls_route("bad.example.com", CERT_A, KEY_B), // KeyMismatch
		];

		let table = build_route_table(
			&specs,
			&ListenerTlsSpec::empty(),
			None,
			&mut TlsConfigCache::new(),
		)
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

	#[test]
	fn non_ascii_sni_is_matched_against_a_wildcard_without_panicking() {
		assert!(!wildcard_suffix_matches(&"é".repeat(7), "example.com"));
		assert!(!wildcard_suffix_matches("ééé.éexample.com", "example.com"));
		assert!(wildcard_suffix_matches("é.example.com", "example.com"));
		assert!(wildcard_suffix_matches("foo.example.com", "example.com"));
		assert!(!wildcard_suffix_matches("a.b.example.com", "example.com"));
		assert!(!wildcard_suffix_matches("fooexample.com", "example.com"));
		assert!(!wildcard_suffix_matches(".example.com", "example.com"));

		let table = build_route_table(
			&[tls_route("*.example.com", CERT_A, KEY_A)],
			&ListenerTlsSpec::empty(),
			None,
			&mut TlsConfigCache::new(),
		)
		.expect("build");
		assert!(table.resolve(Some(&"é".repeat(7))).is_none());
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
			tls_route("", CERT_A, KEY_A),
		];

		let table = build_route_table(
			&specs,
			&ListenerTlsSpec::empty(),
			None,
			&mut TlsConfigCache::new(),
		)
		.expect("build");

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
		let specs = vec![
			tls_route("*.acme.com", CERT_A, KEY_B), // KeyMismatch — dropped
			tls_route("", CERT_A, KEY_A),
		];

		let table = build_route_table(
			&specs,
			&ListenerTlsSpec::empty(),
			None,
			&mut TlsConfigCache::new(),
		)
		.expect("build");

		assert!(
			table.resolve(Some("api.acme.com")).is_none(),
			"a subdomain matching a dropped wildcard must resolve to nothing, not fall through to default"
		);
		assert!(table.resolve(Some("api.other.com")).is_some());
	}

	fn route_name(route: Option<&Route>) -> Option<&str> {
		route.map(|r| r.metric_identity.route.as_ref())
	}

	#[test]
	fn empty_sni_route_is_the_default_for_no_sni_and_unmatched_sni() {
		let specs = vec![
			tls_route("api.acme.com", CERT_A, KEY_A),
			tls_route("*.acme.com", CERT_A, KEY_A),
			tls_route("", CERT_A, KEY_A),
		];
		let table = build(&specs, &ListenerTlsSpec::empty(), None);

		assert_eq!(route_name(table.resolve(None)), Some(""));
		assert_eq!(route_name(table.resolve(Some("example.org"))), Some(""));
		assert_eq!(
			route_name(table.resolve(Some("api.acme.com"))),
			Some("api.acme.com")
		);
		assert_eq!(
			route_name(table.resolve(Some("www.acme.com"))),
			Some("*.acme.com")
		);
		assert_eq!(route_name(table.resolve(Some("a.b.acme.com"))), Some(""));
		assert!(table.resolve_with(None, false).is_none());
		assert!(table.resolve_with(Some("example.org"), false).is_none());
		assert_eq!(table.route_count(), 3);
		assert!(table
			.metric_identities()
			.iter()
			.any(|identity| identity.route.as_ref() == ""));

		let without = build(&specs[..2], &ListenerTlsSpec::empty(), None);
		assert!(without.resolve(None).is_none());
		assert!(without.resolve(Some("example.org")).is_none());
	}

	#[test]
	fn default_route_is_served_without_failover() {
		let default = with_failover(tls_route("", CERT_A, KEY_A), false, "127.0.0.1");
		let table = build(&[default], &ListenerTlsSpec::empty(), None);
		assert!(table.resolve(None).unwrap().failover.is_none());
		assert!(table.failover_routes().is_empty());
		assert_eq!(table.failing_route_count(), 1);
	}

	#[test]
	fn duplicate_default_routes_resolve_last_wins() {
		let mut first = tls_route("", CERT_A, KEY_A);
		first.metrics_group = "first".into();
		let mut last = tls_route("", CERT_A, KEY_A);
		last.metrics_group = "last".into();
		let table = build(&[first, last], &ListenerTlsSpec::empty(), None);
		assert_eq!(
			table.resolve(None).unwrap().metric_identity.group.as_ref(),
			"last"
		);
		assert_eq!(table.route_count(), 1);
	}

	#[test]
	fn default_route_carries_forward_only_under_the_same_client_cert_policy() {
		let listener = ListenerTlsSpec::empty();
		let default_config = |table: &RouteTable| {
			Arc::as_ptr(table.resolve(None).unwrap().tls_config.as_ref().unwrap())
		};
		let live = build(&[tls_route("", CERT_A, KEY_A)], &listener, None);

		let carried = build(&[tls_route("", CERT_A, KEY_B)], &listener, Some(&live));
		assert_eq!(default_config(&carried), default_config(&live));

		let tightened = with_client_ca(tls_route("", CERT_A, KEY_B), CERT_A, true);
		let dropped = build(&[tightened], &listener, Some(&live));
		assert!(dropped.resolve(None).is_none());
		assert!(dropped.resolve(Some("example.org")).is_none());

		let initial = build(&[tls_route("", CERT_A, KEY_B)], &listener, None);
		assert!(initial.resolve(None).is_none());
	}

	// The inverse and more dangerous case: a dropped wildcard must NOT shadow a healthy, more
	// specific exact route at the same suffix. A prior version of the fail-closed check tested
	// `dropped_wildcard` before `exact`, which black-holed every exact route under any wildcard
	// that happened to fail validation — turning one tenant's wildcard typo into an outage for
	// every co-tenant sharing that parent domain.
	#[test]
	fn healthy_exact_route_survives_a_dropped_sibling_wildcard() {
		let specs = vec![
			tls_route("*.acme.com", CERT_A, KEY_B), // KeyMismatch — dropped
			tls_route("api.acme.com", CERT_A, KEY_A), // valid, more specific
		];

		let table = build_route_table(
			&specs,
			&ListenerTlsSpec::empty(),
			None,
			&mut TlsConfigCache::new(),
		)
		.expect("build");

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
		let live = build_route_table(
			&good,
			&ListenerTlsSpec::empty(),
			None,
			&mut TlsConfigCache::new(),
		)
		.expect("initial build");
		let live_route = live
			.resolve(Some("tenant.example.com"))
			.expect("live route");
		let live_identity = live_route.metric_identity.clone();

		// Hot-swap where the same SNI now presents a mismatched pair (mid-rotation).
		let mismatched = vec![tls_route("tenant.example.com", CERT_A, KEY_B)];
		let swapped = build_route_table(
			&mismatched,
			&ListenerTlsSpec::empty(),
			Some(&live),
			&mut TlsConfigCache::new(),
		)
		.expect("hot-swap must not fail");
		assert!(
			swapped.resolve(Some("tenant.example.com")).is_some(),
			"the SNI must keep its last-good route across a transient rebuild failure"
		);
		assert!(Arc::ptr_eq(
			&swapped
				.resolve(Some("tenant.example.com"))
				.unwrap()
				.metric_identity,
			&live_identity
		));
		assert!(
			swapped.failing_snis.contains("tenant.example.com"),
			"the transiently-failing SNI must be tracked so it isn't re-logged every reconcile"
		);

		// With no previous table (initial build), the same bad route is dropped.
		let fresh = build_route_table(
			&mismatched,
			&ListenerTlsSpec::empty(),
			None,
			&mut TlsConfigCache::new(),
		)
		.expect("build");
		assert!(
			fresh.resolve(Some("tenant.example.com")).is_none(),
			"with no prior route there is nothing to retain — the SNI is dropped"
		);
	}

	fn with_client_ca(mut spec: RouteSpec, ca: &[u8], required: bool) -> RouteSpec {
		spec.mtls_ca_pem = Some(ca.to_vec());
		spec.require_client_cert = required;
		spec
	}

	fn build(
		specs: &[RouteSpec],
		listener: &ListenerTlsSpec,
		live: Option<&RouteTable>,
	) -> RouteTable {
		build_route_table(specs, listener, live, &mut TlsConfigCache::new()).expect("build")
	}

	fn with_failover(mut spec: RouteSpec, drain: bool, peer: &str) -> RouteSpec {
		spec.upstreams = vec![UpstreamSpec::Uds {
			paths: vec!["/tmp/symphony-failover-test.sock".into()],
			pids: vec![None],
			tids: vec![None],
			ip_affinity: false,
			affinity_ttl_ms: 1,
			protocol: None,
		}];
		spec.failover = Some(FailoverSpec {
			peers: vec![(peer.into(), 9443)],
			drain,
			probe_interval_ms: None,
			cooldown_min_ms: None,
			cooldown_max_ms: None,
		});
		spec
	}

	#[test]
	fn a_carried_forward_route_takes_the_new_failover_policy() {
		let sni = "tenant.example.com";
		let live = build(
			&[with_failover(
				tls_route(sni, CERT_A, KEY_A),
				false,
				"10.0.0.2",
			)],
			&ListenerTlsSpec::empty(),
			None,
		);
		let live_failover = live.resolve(Some(sni)).unwrap().failover.clone().unwrap();
		live_failover.peers[0]
			.forwarded
			.fetch_add(7, Ordering::Relaxed);

		let swapped = build(
			&[with_failover(
				tls_route(sni, CERT_A, KEY_B),
				true,
				"10.0.0.2",
			)],
			&ListenerTlsSpec::empty(),
			Some(&live),
		);
		let route = swapped.resolve(Some(sni)).unwrap();
		assert!(
			swapped.failing_snis.contains(sni),
			"the cert failure carried the route forward"
		);
		let failover = route.failover.as_ref().unwrap();
		assert!(
			failover.drain,
			"drain from the new spec applies to the retained route"
		);
		assert!(Arc::ptr_eq(&failover.peers[0], &live_failover.peers[0]));
		assert_eq!(swapped.failover_routes().len(), 1);
	}

	fn tracked(route: &Route) -> bool {
		match &route.destination {
			Destination::UdsSet(balancer) => balancer.tracked_slots().next().is_some(),
			Destination::Tcp(_) => panic!("expected a UDS destination"),
		}
	}

	#[test]
	fn a_carried_forward_route_tracks_health_exactly_when_it_has_failover() {
		let sni = "tenant.example.com";
		let mut plain = with_failover(tls_route(sni, CERT_A, KEY_A), false, "10.0.0.2");
		plain.failover = None;
		let live = build(
			std::slice::from_ref(&plain),
			&ListenerTlsSpec::empty(),
			None,
		);
		assert!(!tracked(live.resolve(Some(sni)).unwrap()));

		// Failover enabled (and the upstream moved) in the same reload that a cert rotation breaks.
		let mut enabling = with_failover(tls_route(sni, CERT_A, KEY_B), false, "10.0.0.2");
		if let UpstreamSpec::Uds { paths, .. } = &mut enabling.upstreams[0] {
			paths[0] = "/tmp/symphony-failover-moved.sock".into();
		}
		let enabled = build(&[enabling], &ListenerTlsSpec::empty(), Some(&live));
		let route = enabled.resolve(Some(sni)).unwrap();
		assert!(enabled.failing_snis.contains(sni));
		assert!(route.failover.is_some());
		match &route.destination {
			Destination::UdsSet(balancer) => assert_eq!(
				balancer.path(0).as_ref(),
				"/tmp/symphony-failover-test.sock",
				"the carried route keeps its own upstream until the cert heals"
			),
			Destination::Tcp(_) => unreachable!(),
		}
		assert!(tracked(route), "rebuilt so the probe has slots to clear");

		// And removed again while the cert is still broken.
		let mut removed_spec = tls_route(sni, CERT_A, KEY_B);
		removed_spec.upstreams = plain.upstreams.clone();
		let removed = build(&[removed_spec], &ListenerTlsSpec::empty(), Some(&enabled));
		let route = removed.resolve(Some(sni)).unwrap();
		assert!(route.failover.is_none());
		assert!(!tracked(route), "no tracked slot is left without a probe");
	}

	#[test]
	fn an_invalid_failover_policy_serves_the_route_without_failover() {
		let sni = "tenant.example.com";
		let table = build(
			&[with_failover(
				tls_route(sni, CERT_A, KEY_A),
				false,
				"peer.example",
			)],
			&ListenerTlsSpec::empty(),
			None,
		);
		let route = table.resolve(Some(sni)).expect("route still served");
		assert!(route.failover.is_none());
		assert!(table.invalid_failover.contains(sni));
		assert!(
			!table.failing_snis.contains(sni),
			"a later cert failure still logs"
		);
		assert_eq!(table.failing_route_count(), 1);
		assert!(table.failover_routes().is_empty());
		match &route.destination {
			Destination::UdsSet(balancer) => assert_eq!(
				balancer.tracked_slots().count(),
				0,
				"no health tracking without a probe to clear it"
			),
			Destination::Tcp(_) => panic!("expected a UDS destination"),
		}
	}

	#[test]
	fn a_failover_rebuild_shares_slot_health_with_the_previous_table() {
		let sni = "tenant.example.com";
		let spec = with_failover(tls_route(sni, CERT_A, KEY_A), false, "10.0.0.2");
		let live = build(std::slice::from_ref(&spec), &ListenerTlsSpec::empty(), None);
		let rebuilt = build(&[spec], &ListenerTlsSpec::empty(), Some(&live));
		let health = |table: &RouteTable| match &table.resolve(Some(sni)).unwrap().destination {
			Destination::UdsSet(balancer) => balancer.health(0).unwrap().clone(),
			Destination::Tcp(_) => panic!("expected a UDS destination"),
		};
		assert!(Arc::ptr_eq(&health(&live), &health(&rebuilt)));
	}

	/// A passthrough spec whose build fails: every upstream is h2-marked, so it has no default one.
	fn failing_passthrough(sni: &str) -> RouteSpec {
		let mut spec = tls_route(sni, CERT_A, KEY_A);
		spec.terminate_tls = false;
		spec.upstreams = vec![UpstreamSpec::Uds {
			paths: vec!["/nonexistent/h2.sock".into()],
			pids: vec![None],
			tids: vec![None],
			ip_affinity: false,
			affinity_ttl_ms: 0,
			protocol: Some("h2".into()),
		}];
		spec
	}

	// symphony#62
	#[test]
	fn failed_rebuild_under_a_new_client_cert_policy_is_dropped() {
		let listener = ListenerTlsSpec::empty();
		let wildcard = tls_route("*.example.com", CERT_A, KEY_A);
		let live = build(
			&[
				tls_route("tenant.example.com", CERT_A, KEY_A),
				wildcard.clone(),
			],
			&listener,
			None,
		);
		assert!(live.resolve(Some("tenant.example.com")).is_some());

		let required_with_no_trust_anchors =
			with_client_ca(tls_route("tenant.example.com", CERT_A, KEY_A), b"", true);
		let failing = [required_with_no_trust_anchors, wildcard.clone()];
		let swapped = build(&failing, &listener, Some(&live));
		assert!(
			swapped.resolve(Some("tenant.example.com")).is_none(),
			"the old route admits certless clients the new policy refuses, so it must not be retained, and the SNI must not fall through to the wildcard"
		);
		assert!(swapped.failing_snis.contains("tenant.example.com"));
		assert!(
			swapped.resolve(Some("other.example.com")).is_some(),
			"the healthy wildcard keeps serving its own subdomains"
		);

		let again = build(&failing, &listener, Some(&swapped));
		assert!(again.resolve(Some("tenant.example.com")).is_none());

		let buildable =
			with_client_ca(tls_route("tenant.example.com", CERT_A, KEY_A), CERT_A, true);
		let healed = build(&[buildable, wildcard], &listener, Some(&again));
		assert!(healed.resolve(Some("tenant.example.com")).is_some());
		assert_eq!(healed.failing_route_count(), 0);
	}

	#[test]
	fn a_rejected_duplicate_is_not_replaced_by_its_sibling() {
		let listener = ListenerTlsSpec::empty();
		for (sni, probe) in [
			("tenant.example.com", "tenant.example.com"),
			("*.example.com", "app.example.com"),
		] {
			let certless = tls_route(sni, CERT_A, KEY_A);
			let rejected = with_client_ca(certless.clone(), b"", true);
			let live = build(std::slice::from_ref(&certless), &listener, None);
			let deciding_rejected = if sni.starts_with("*.") {
				[rejected.clone(), certless.clone()]
			} else {
				[certless.clone(), rejected.clone()]
			};
			for previous in [None, Some(&live)] {
				let table = build(&deciding_rejected, &listener, previous);
				assert!(
					table.resolve(Some(probe)).is_none(),
					"{sni}: a certless duplicate must not serve the SNI its deciding spec requires certs for"
				);
			}

			let mut deciding_buildable = deciding_rejected;
			deciding_buildable.reverse();
			let table = build(&deciding_buildable, &listener, Some(&live));
			assert!(
				table.resolve(Some(probe)).is_some(),
				"{sni}: a buildable deciding duplicate serves"
			);
		}
	}

	#[test]
	fn cert_only_failure_keeps_last_good_while_the_client_cert_policy_is_unchanged() {
		let listener = ListenerTlsSpec::empty();
		let specs = |key: &[u8], required: bool| {
			["tenant.example.com", "*.example.com"]
				.map(|sni| with_client_ca(tls_route(sni, CERT_A, key), CERT_A, required))
		};
		let live = build(&specs(KEY_A, true), &listener, None);

		let carried = build(&specs(KEY_B, true), &listener, Some(&live));
		for sni in ["tenant.example.com", "other.example.com"] {
			assert_eq!(
				config_ptr(&carried, sni),
				config_ptr(&live, sni),
				"{sni}: a mismatched key under an unchanged policy keeps the last-good route"
			);
		}

		let dropped = build(&specs(KEY_B, false), &listener, Some(&carried));
		for sni in ["tenant.example.com", "other.example.com"] {
			assert!(
				dropped.resolve(Some(sni)).is_none(),
				"{sni}: a carried-forward route must not outlive a client-cert policy change"
			);
		}
	}

	#[test]
	fn every_client_auth_change_drops_a_failing_route() {
		let listener = ListenerTlsSpec::empty();
		let sni = "tenant.example.com";
		let terminated = tls_route(sni, CERT_A, KEY_A);
		let required = with_client_ca(terminated.clone(), CERT_A, true);
		let mut other_bundle = CERT_A.to_vec();
		other_bundle.extend_from_slice(b"# a different bundle\n");
		let mismatched = |spec: &RouteSpec| RouteSpec {
			key_pem: Some(KEY_B.to_vec()),
			..spec.clone()
		};

		let cases = [
			("client CA removed", &required, mismatched(&terminated)),
			(
				"client cert made optional",
				&required,
				mismatched(&with_client_ca(terminated.clone(), CERT_A, false)),
			),
			(
				"client CA bundle changed",
				&required,
				mismatched(&with_client_ca(terminated.clone(), &other_bundle, true)),
			),
			(
				"client CA added",
				&terminated,
				mismatched(&with_client_ca(terminated.clone(), CERT_A, true)),
			),
			(
				"terminating route switched to passthrough",
				&terminated,
				failing_passthrough(sni),
			),
		];
		for (change, previous, failing) in cases {
			let live = build(std::slice::from_ref(previous), &listener, None);
			assert!(live.resolve(Some(sni)).is_some(), "{change}: live route");
			let swapped = build(&[failing], &listener, Some(&live));
			assert!(
				swapped.resolve(Some(sni)).is_none(),
				"{change}: the last-good route must not be retained"
			);
		}
	}

	#[test]
	fn client_auth_inherited_from_the_listener_compares_by_effect() {
		let listener = ListenerTlsSpec {
			mtls_ca_pem: Some(CERT_A.to_vec()),
			require_client_cert: true,
			..ListenerTlsSpec::empty()
		};
		let sni = "tenant.example.com";
		let live = build(&[tls_route(sni, CERT_A, KEY_A)], &listener, None);

		let same_effect = with_client_ca(tls_route(sni, CERT_A, KEY_B), CERT_A, true);
		let carried = build(&[same_effect], &listener, Some(&live));
		assert_eq!(config_ptr(&carried, sni), config_ptr(&live, sni));

		let optional = with_client_ca(tls_route(sni, CERT_A, KEY_B), CERT_A, false);
		let dropped = build(&[optional], &listener, Some(&live));
		assert!(dropped.resolve(Some(sni)).is_none());
	}

	#[test]
	fn route_metric_identity_survives_reload_until_group_changes() {
		let mut initial = tls_route("tenant.example.com", CERT_A, KEY_A);
		initial.metrics_group = "tenant-1".to_string();
		let mut cache = TlsConfigCache::new();
		let live = build_route_table(
			&[initial.clone()],
			&ListenerTlsSpec::empty(),
			None,
			&mut cache,
		)
		.expect("initial build");
		let live_identity = live
			.resolve(Some("tenant.example.com"))
			.unwrap()
			.metric_identity
			.clone();

		let reloaded = build_route_table(
			&[initial.clone()],
			&ListenerTlsSpec::empty(),
			Some(&live),
			&mut cache,
		)
		.expect("reload");
		assert!(Arc::ptr_eq(
			&reloaded
				.resolve(Some("tenant.example.com"))
				.unwrap()
				.metric_identity,
			&live_identity
		));

		initial.metrics_group = "tenant-2".to_string();
		let regrouped = build_route_table(
			&[initial],
			&ListenerTlsSpec::empty(),
			Some(&reloaded),
			&mut cache,
		)
		.expect("regroup");
		assert!(!Arc::ptr_eq(
			&regrouped
				.resolve(Some("tenant.example.com"))
				.unwrap()
				.metric_identity,
			&live_identity
		));
	}

	#[test]
	fn duplicate_route_identity_is_isolated() {
		let route = tls_route("*.tenant.example.com", CERT_A, KEY_A);
		let table = build_route_table(
			&[route.clone(), route],
			&ListenerTlsSpec::empty(),
			None,
			&mut TlsConfigCache::new(),
		)
		.expect("a duplicate must not abort the table");
		assert_eq!(table.metric_identities().len(), 1);
		assert!(table.resolve(Some("app.tenant.example.com")).is_some());
		assert_eq!(table.failing_route_count(), 1);
	}

	#[test]
	fn duplicate_exact_route_preserves_last_wins_behavior() {
		let mut first = tls_route("tenant.example.com", CERT_A, KEY_A);
		first.metrics_group = "first".to_string();
		let mut second = first.clone();
		second.metrics_group = "second".to_string();
		let table = build_route_table(
			&[first, second],
			&ListenerTlsSpec::empty(),
			None,
			&mut TlsConfigCache::new(),
		)
		.expect("build");
		assert_eq!(table.metric_identities().len(), 1);
		assert_eq!(table.metric_identities()[0].group.as_ref(), "second");
		assert_eq!(table.failing_route_count(), 0);
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
		let live = build_route_table(
			&[good],
			&ListenerTlsSpec::empty(),
			None,
			&mut TlsConfigCache::new(),
		)
		.expect("initial build");
		assert!(live.resolve(Some("tenant.example.com")).is_some());

		// Hot-swap drops the protocol declaration — a permanent rejection, not a transient one.
		let mut broken = tls_route("tenant.example.com", CERT_A, KEY_A);
		broken.source_address_mode = SourceAddressMode::XForwardedFor;
		// protocol left at its default (Opaque) — undeclared.
		let swapped = build_route_table(
			&[broken],
			&ListenerTlsSpec::empty(),
			Some(&live),
			&mut TlsConfigCache::new(),
		)
		.expect("hot-swap must not fail");
		assert!(
			swapped.resolve(Some("tenant.example.com")).is_none(),
			"a permanent protocol-declaration rejection must drop the route, not silently carry the previous one forward"
		);
	}

	#[test]
	fn header_injection_detection() {
		const JA3: ForwardFingerprint = ForwardFingerprint {
			ja3: true,
			ja4: false,
		};
		const JA4: ForwardFingerprint = ForwardFingerprint {
			ja3: false,
			ja4: true,
		};
		const BOTH: ForwardFingerprint = ForwardFingerprint {
			ja3: true,
			ja4: true,
		};
		// xForwardedFor always needs protocol: 'http', regardless of fingerprint.
		assert!(requires_http_protocol(
			SourceAddressMode::XForwardedFor,
			ForwardFingerprint::NONE
		));
		// A header-carried fingerprint (any mode other than proxyProtocolV2) needs it too.
		assert!(requires_http_protocol(SourceAddressMode::None, JA3));
		assert!(requires_http_protocol(
			SourceAddressMode::ProxyProtocol,
			JA4
		));
		assert!(requires_http_protocol(SourceAddressMode::None, BOTH));
		// proxyProtocolV2 carries the fingerprint as a TLV — never needs the declaration.
		assert!(!requires_http_protocol(
			SourceAddressMode::ProxyProtocolV2,
			JA3
		));
		assert!(!requires_http_protocol(
			SourceAddressMode::ProxyProtocolV2,
			BOTH
		));
		// No header-injection mode requested at all.
		assert!(!requires_http_protocol(
			SourceAddressMode::None,
			ForwardFingerprint::NONE
		));
		assert!(!requires_http_protocol(
			SourceAddressMode::ProxyProtocol,
			ForwardFingerprint::NONE
		));
	}

	fn uds_upstream(path: &str, protocol: Option<&str>, ip_affinity: bool) -> UpstreamSpec {
		UpstreamSpec::Uds {
			paths: vec![path.to_string()],
			pids: vec![None],
			tids: vec![None],
			ip_affinity,
			affinity_ttl_ms: 0,
			protocol: protocol.map(str::to_string),
		}
	}

	/// A terminating route whose UDS upstreams include an h2 mirror, so it gets two balancers.
	fn affinity_route(key: &[u8], ip_affinity: bool) -> RouteSpec {
		let mut spec = tls_route("tenant.example.com", CERT_A, key);
		spec.http2 = true;
		spec.upstreams = vec![
			uds_upstream("/tmp/symphony-test.sock", None, ip_affinity),
			uds_upstream("/tmp/symphony-test-h2.sock", Some("h2"), ip_affinity),
		];
		spec
	}

	#[test]
	fn affinity_balancers_come_from_the_installed_route() {
		let mut cache = TlsConfigCache::new();
		let no_affinity = build_route_table(
			&[affinity_route(KEY_A, false)],
			&ListenerTlsSpec::empty(),
			None,
			&mut cache,
		)
		.expect("build");
		assert!(no_affinity.affinity_balancers.is_empty());

		let live = build_route_table(
			&[affinity_route(KEY_A, true)],
			&ListenerTlsSpec::empty(),
			Some(&no_affinity),
			&mut cache,
		)
		.expect("build");
		assert_eq!(
			live.affinity_balancers.len(),
			2,
			"the h2 mirror's balancer carries its own affinity map"
		);

		// A cert mismatch carries the live route forward — affinity and all — even though the
		// rejected spec turned affinity off. Its maps keep growing, so they must stay collected.
		let carried = build_route_table(
			&[affinity_route(KEY_B, false)],
			&ListenerTlsSpec::empty(),
			Some(&live),
			&mut cache,
		)
		.expect("carry forward");
		assert_eq!(carried.affinity_balancers.len(), 2);
		assert!(carried
			.affinity_balancers
			.iter()
			.zip(&live.affinity_balancers)
			.all(|(a, b)| Arc::ptr_eq(a, b)));
	}

	#[tokio::test]
	async fn affinity_eviction_follows_the_live_table_and_stops_on_shutdown() {
		let mut cache = TlsConfigCache::new();
		let live = LiveRouteTable::new(
			build_route_table(&[], &ListenerTlsSpec::empty(), None, &mut cache).expect("build"),
		);
		let (shutdown_tx, shutdown_rx) = broadcast::channel(1);
		let task = tokio::spawn(evict_affinity_periodically(
			live.clone(),
			Duration::from_millis(5),
			shutdown_rx,
		));

		// Affinity arrives with a reload after the task started, so it has to re-read the table.
		live.swap(
			build_route_table(
				&[affinity_route(KEY_A, true)],
				&ListenerTlsSpec::empty(),
				None,
				&mut cache,
			)
			.expect("build"),
		);
		let balancers = live.0.load().affinity_balancers.clone();
		for balancer in &balancers {
			balancer.pick(Some("192.0.2.7".parse().unwrap()));
			assert_eq!(balancer.affinity_len(), 1);
		}

		let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
		while balancers.iter().any(|b| b.affinity_len() > 0) {
			assert!(
				tokio::time::Instant::now() < deadline,
				"expired affinity entries were never reclaimed"
			);
			tokio::time::sleep(Duration::from_millis(5)).await;
		}

		shutdown_tx.send(()).unwrap();
		tokio::time::timeout(Duration::from_secs(5), task)
			.await
			.expect("the task must exit on shutdown")
			.unwrap();
	}

	fn allowlist(entries: &[&str]) -> SourceAllowlist {
		let entries: Vec<String> = entries.iter().map(|e| e.to_string()).collect();
		SourceAllowlist::parse(&entries)
			.expect("valid")
			.expect("non-empty")
	}

	fn ip(s: &str) -> IpAddr {
		s.parse().unwrap()
	}

	#[test]
	fn source_allowlist_matches_v4_v6_and_bare_hosts() {
		let allowed = allowlist(&["10.0.0.0/8", "2001:db8::/32", "192.0.2.7"]);
		assert!(allowed.permits(ip("10.1.2.3")));
		assert!(allowed.permits(ip("2001:db8::1")));
		assert!(allowed.permits(ip("192.0.2.7")));
		assert!(!allowed.permits(ip("192.0.2.8")));
		assert!(!allowed.permits(ip("11.0.0.1")));
		assert!(!allowed.permits(ip("2001:db9::1")));
	}

	#[test]
	fn source_allowlist_matches_ipv4_mapped_peers_and_cidrs_as_ipv4() {
		let v4 = allowlist(&["10.0.0.0/8"]);
		assert!(v4.permits(ip("::ffff:10.1.2.3")));
		assert!(!v4.permits(ip("::ffff:11.1.2.3")));

		let mapped = allowlist(&["::ffff:10.0.0.0/104"]);
		assert!(mapped.permits(ip("10.1.2.3")));
		assert!(mapped.permits(ip("::ffff:10.1.2.3")));
		assert!(!mapped.permits(ip("11.1.2.3")));

		// `::` is not an IPv4-mapped address, so `::/0` stays v6 and matches only native v6 peers.
		let broad = allowlist(&["::/0"]);
		assert!(broad.permits(ip("2001:db8::1")));
		assert!(!broad.permits(ip("10.1.2.3")));
	}

	#[test]
	fn source_allowlist_parse_empty_and_invalid() {
		assert!(SourceAllowlist::parse(&[]).unwrap().is_none());
		for bad in ["nope", "10.0.0.0/33", "", " 10.0.0.1", "::ffff:10.0.0.0/8"] {
			let err = SourceAllowlist::parse(&["10.0.0.0/8".into(), bad.into()]).unwrap_err();
			assert!(err.contains(&format!("'{bad}'")), "{err}");
		}
	}

	#[test]
	fn invalid_allowed_sources_drops_only_that_route_and_fails_closed() {
		let listener = ListenerTlsSpec::empty();
		let wildcard = tls_route("*.example.com", CERT_A, KEY_A);
		let mut bad = tls_route("tenant.example.com", CERT_A, KEY_A);
		bad.allowed_sources = vec!["10.0.0.0/8".into(), "not-a-cidr".into()];

		let table = build(&[wildcard.clone(), bad.clone()], &listener, None);
		assert!(
			table.resolve(Some("tenant.example.com")).is_none(),
			"a rejected list must not fall through to the wildcard"
		);
		assert!(table.resolve(Some("other.example.com")).is_some());
		assert_eq!(table.failing_route_count(), 1);

		// On a hot-swap there is no carry-forward either: the previous route had no restriction.
		let live = build(
			&[
				wildcard.clone(),
				tls_route("tenant.example.com", CERT_A, KEY_A),
			],
			&listener,
			None,
		);
		let swapped = build(&[wildcard, bad], &listener, Some(&live));
		assert!(swapped.resolve(Some("tenant.example.com")).is_none());
	}

	#[test]
	fn a_carried_forward_route_enforces_the_new_allowed_sources() {
		let listener = ListenerTlsSpec::empty();
		let sni = "tenant.example.com";
		let mut live_spec = tls_route(sni, CERT_A, KEY_A);
		live_spec.allowed_sources = vec!["10.0.0.0/8".into(), "192.0.2.0/24".into()];
		let live = build(&[live_spec], &listener, None);

		// KEY_B does not match CERT_A, so the rebuild fails and the last-good route is retained.
		let mut narrowed = tls_route(sni, CERT_A, KEY_B);
		narrowed.allowed_sources = vec!["192.0.2.0/24".into()];
		let swapped = build(&[narrowed.clone()], &listener, Some(&live));
		assert!(swapped.failing_snis.contains(sni));
		let route = swapped
			.resolve(Some(sni))
			.expect("last-good route retained");
		let allowed = route.allowed_sources.as_ref().expect("restricted");
		assert!(allowed.permits(ip("192.0.2.1")));
		assert!(
			!allowed.permits(ip("10.0.0.1")),
			"the removed CIDR must stop admitting"
		);

		narrowed.allowed_sources.clear();
		let lifted = build(&[narrowed], &listener, Some(&live));
		assert!(lifted.resolve(Some(sni)).unwrap().allowed_sources.is_none());
	}
}
