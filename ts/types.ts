// ── Upstream types ────────────────────────────────────────────────────────────

export interface TcpUpstream {
	kind: 'tcp';
	host: string;
	port: number;
}

export interface UdsUpstream {
	kind: 'uds';
	/** Path to the Unix domain socket. Provide multiple UdsUpstream entries for load balancing. */
	path: string;
	/** Route connections from the same source IP to the same socket. Default: false. */
	ipAffinity?: boolean;
	/** How long (ms) an IP→socket mapping is retained with no new connections. Default: 300000. */
	ipAffinityTtlMs?: number;
	/**
	 * Linux process ID of the worker serving this socket.
	 * When provided alongside `tid`, symphony samples /proc/{pid}/task/{tid}/stat
	 * every 250 ms and uses the measured CPU utilisation as a secondary tiebreaker
	 * in socket selection (active connections remain the primary factor).
	 */
	pid?: number;
	/** Linux thread ID (TID) of the worker serving this socket. Must be set together with `pid`. */
	tid?: number;
	/**
	 * Application protocol this socket speaks. `'h2'` marks a cleartext HTTP/2
	 * upstream (e.g. Harper's `<worker>-<port>-h2.sock` mirror, whose UDS metadata
	 * yaml carries `protocol: h2`): when the route also sets `http2: true`,
	 * connections that negotiate `h2` in ALPN are forwarded here, while all other
	 * connections use the route's unmarked (HTTP/1.x) upstreams. A route with any
	 * `'h2'` upstream must keep at least one unmarked upstream, and cannot use
	 * `sourceAddressHeader: 'xForwardedFor'` (header injection would corrupt h2
	 * frames — use `'proxyProtocol'`, which rides before the h2 preface, or `'none'`).
	 * Default: HTTP/1.x.
	 */
	protocol?: 'h2' | 'http/1.1';
}

export type Upstream = TcpUpstream | UdsUpstream;

// ── TLS / mTLS ────────────────────────────────────────────────────────────────

export interface CertConfig {
	certChain: string | Buffer;
	privateKey: string | Buffer;
}

export interface MtlsConfig {
	clientCaCert: string | Buffer;
	/** Whether to reject clients that do not present a certificate. Default: false (optional client cert). */
	requireClientCert?: boolean;
}

// ── Route config ──────────────────────────────────────────────────────────────

export interface RouteConfig {
	/**
	 * SNI hostname to match. Exact match (e.g. "api.example.com") or wildcard
	 * left-label (e.g. "*.example.com"). Use "" for the default/catch-all route. Maximum 255
	 * UTF-8 bytes; control characters are rejected.
	 */
	sni: string;
	/**
	 * Stable grouping key for aggregating several domain routes as one tenant. Maximum 128 UTF-8
	 * bytes; control characters are rejected.
	 */
	metricsGroup?: string;
	upstreams: Upstream[];
	/**
	 * When true, the proxy terminates TLS and forwards plaintext to the upstream.
	 * When false, raw TLS bytes are forwarded unchanged (passthrough mode).
	 */
	terminateTls: boolean;
	/** Per-route certificate, overrides the listener defaultCert. */
	cert?: CertConfig;
	/** Per-route mTLS config, overrides the listener mtls. */
	mtls?: MtlsConfig;
	/**
	 * When true, incoming connections are held and a 'suspended' event is emitted.
	 * Call resolveConnection() to proxy or reject each held connection.
	 * The upstreams field is ignored while suspended.
	 */
	suspended?: boolean;
	/** Max ms to wait for resolveConnection() before dropping the connection. Default: 30000. */
	suspendTimeoutMs?: number;
	/**
	 * Global rate limit for this route (new connections per second, route-wide — not per IP).
	 * Connections are silently dropped (TCP RST) when the token bucket is exhausted.
	 * Use this to prevent one route from starving others under high load.
	 */
	maxConnectionsPerSecond?: number;
	/** Token bucket burst ceiling (connections). Defaults to maxConnectionsPerSecond. */
	burst?: number;
	/**
	 * How the real client IP is forwarded to the upstream.
	 *
	 * - `'proxyProtocol'` — Send a PROXY protocol v1 (text) header before application data.
	 *   Default for UDS upstreams.
	 * - `'proxyProtocolV2'` — Send a PROXY protocol v2 (binary) header before application
	 *   data. v2 carries a TLV section: the carrier for `forwardFingerprint`, and — when
	 *   `terminateTls: true` — the connection's TLS facts: ALPN (0x01), SNI authority
	 *   (0x02), an SSL TLV (0x20, version/cipher sub-TLVs and a client-cert-present bit),
	 *   and, when the client presented a certificate the `mtls` verifier accepted, the
	 *   full client certificate chain as one DER TLV per certificate (custom type 0xE2,
	 *   leaf first). Keep opt-in: consumers must speak v2 (HAProxy/nginx do; Harper
	 *   core's UDS reader parses v1 only before Harper 5.2).
	 * - `'xForwardedFor'` — Parse the beginning of the HTTP request and insert an
	 *   `X-Forwarded-For` header. Use this for backends (e.g. Bun) that do not
	 *   support the PROXY protocol.
	 * - `'none'` — Do not forward source address information. Default for TCP upstreams.
	 */
	sourceAddressHeader?: 'proxyProtocol' | 'proxyProtocolV2' | 'xForwardedFor' | 'none';
	/**
	 * Forward the client's TLS fingerprint (computed from the ClientHello) downstream so the
	 * upstream can make its own bot/abuse decisions on it.
	 *
	 * - `'ja3'` / `'ja4'` — forward that fingerprint.
	 * - `['ja3', 'ja4']` — forward both (e.g. while migrating a JA3-keyed blocklist to JA4).
	 *   List order does not matter; JA3 is always emitted before JA4.
	 * - `'none'` (default) — do not forward.
	 *
	 * Every selected fingerprint rides the same carrier: a PROXY v2 TLV when
	 * `sourceAddressHeader` is `'proxyProtocolV2'` (works in passthrough too, since it
	 * prefixes the raw TLS bytes); otherwise an injected `X-JA3` / `X-JA4` HTTP header, which
	 * requires a plaintext HTTP/1 upstream (`terminateTls: true` and not `http2`) — it is
	 * skipped otherwise. For that HTTP/1 case, the client-supplied copy of each forwarded
	 * header is stripped so the injected value is authoritative — but this does NOT hold on an h2-negotiated connection on an `http2: true` route: injection
	 * and stripping are both skipped there, so a client-supplied `X-JA3` / `X-JA4` reaches the
	 * upstream unmodified. Use `'proxyProtocolV2'` wherever h2 is possible.
	 */
	forwardFingerprint?: 'ja3' | 'ja4' | 'none' | ('ja3' | 'ja4')[];
	/**
	 * Advertise HTTP/2 (`h2`) in the TLS ALPN extension so clients can negotiate
	 * HTTP/2. When true, symphony declares `['h2', 'http/1.1']` in ALPN and the
	 * upstream receives raw HTTP/2 frames over the plaintext socket — no translation.
	 * Requires `terminateTls: true`. Default: false.
	 */
	http2?: boolean;
	/**
	 * The route's application protocol.
	 *
	 * - `'http'` — the byte stream (once TLS is terminated and h2 isn't negotiated) is
	 *   HTTP/1.x. Required to use `sourceAddressHeader: 'xForwardedFor'`, or
	 *   `forwardFingerprint` under any mode other than `'proxyProtocolV2'` — both rewrite
	 *   an HTTP request, which is only safe on a route that says it carries one.
	 * - `'opaque'` (default) — not HTTP: MQTT, a raw TCP protocol, or anything else
	 *   symphony doesn't parse. Source-address forwarding is limited to the
	 *   `'proxyProtocol'` / `'proxyProtocolV2'` carriers, which work on any byte stream.
	 *
	 * ALPN cannot stand in for this declaration: a native non-HTTP client that offers no
	 * ALPN is indistinguishable from an HTTPS client that simply didn't offer one, so a
	 * route requesting a header-injection mode without declaring `protocol: 'http'` is a
	 * config error, not a route that quietly stops injecting the header — the route is
	 * rejected and dropped (isolated the same way a route with a bad cert is, not failing
	 * `new SymphonyProxy()`/`updateConfig()` for every other route on the port-set). This is
	 * a breaking change for a hand-written route using `sourceAddressHeader: 'xForwardedFor'`
	 * (or a header-carried `forwardFingerprint`) without `protocol: 'http'` — add the
	 * declaration, or that route will stop serving traffic on upgrade.
	 */
	protocol?: 'http' | 'opaque';
	/**
	 * Restrict the route to these client addresses: CIDRs, IPv4 or IPv6 (`'203.0.113.0/24'`,
	 * `'2001:db8::/32'`); a bare IP is a single host. Absent or empty = any client.
	 *
	 * Matched against the TCP peer address symphony sees, never a PROXY header or
	 * `X-Forwarded-For`. An IPv4 client reaching a dual-stack (`::`) listener is matched as IPv4.
	 * A refused connection is closed before the TLS handshake, the upstream connect, the route
	 * rate limiter and any `'suspended'` event, and counted as `source_not_allowed` in the
	 * route's and listener's `blockedByReason`.
	 *
	 * Applies on every listener that resolves this route, including an HTTP listener's ACME
	 * HTTP-01 proxy — so a list on a route served by an ACME listener also refuses the CA's
	 * validators. The list is checked once, when a connection is admitted: an `updateConfig()`
	 * that changes it applies to new connections, and established ones are not dropped.
	 *
	 * It restricts this route, not its upstream: the client chooses the SNI, so every route that
	 * reaches a restricted upstream needs the same list.
	 *
	 * An invalid entry drops this route (it then refuses every connection, counted in
	 * `failingRoutes`) rather than failing `new SymphonyProxy()`/`updateConfig()` for every other
	 * route on the port-set.
	 */
	allowedSources?: string[];
	/**
	 * Send new connections to peer nodes while this route's local upstream is down, or always
	 * when `drain` is set. The connection is forwarded as raw TLS, before any handshake, to a
	 * peer's `failoverIngress` listener, which terminates it with its own copy of the
	 * certificate. Connections already established are never moved.
	 *
	 * An invalid policy serves the route without failover (counted in `failingRoutes`).
	 */
	failover?: FailoverConfig;
}

export interface FailoverPeer {
	/** IP literal of the peer's failover ingress listener. Hostnames are not resolved. */
	host: string;
	port: number;
}

export interface FailoverConfig {
	/** Tried round-robin, skipping peers in cooldown. At least one. */
	peers: FailoverPeer[];
	/**
	 * Forward every new connection whatever the local health — for a local upstream that is up
	 * but unhealthy. A `failoverIngress` listener also refuses forwarded connections for a
	 * draining route, so peers move on. Default: false.
	 */
	drain?: boolean;
	/**
	 * How often a refusing local upstream slot is re-tested (connect, then close). Minimum 10.
	 * Default: 1000.
	 */
	probeIntervalMs?: number;
	/**
	 * After a failed attempt a peer is skipped for `min` ms, doubling per consecutive failure up to
	 * `max`; one success resets it. Per (route, peer). Default: `{ min: 5000, max: 60000 }`.
	 */
	peerCooldownMs?: { min: number; max: number };
	/**
	 * While the local upstream is up, also forward a share of new connections to the least-loaded
	 * peer when this route's Harper threads are much busier than the same route's on that peer.
	 * Loads come from each node's worker-thread CPU (UDS upstreams with `pid`/`tid`) and are
	 * exchanged over the peers' `failoverIngress` listeners. Exact-SNI routes only; an invalid
	 * policy disables only spill-over (counted in `failingRoutes`). `{}` enables the defaults.
	 */
	spill?: SpillConfig;
}

export interface SpillConfig {
	/** Local load (0–1, mean of the worker threads' CPU) at which spilling may start. Default: 0.75. */
	highWater?: number;
	/**
	 * How far below the local load (0–1) the target peer must report to raise the share; it is held
	 * while the gap is at least half this. Default: 0.2.
	 */
	margin?: number;
	/** Change of the spilled share per second, up and down. Default: 0.05. */
	step?: number;
	/** Largest share (0–1) of new connections spilled. Default: 0.5. */
	maxFraction?: number;
	/** Spill only to peers whose measured connect time is at most this many ms. Default: no limit. */
	maxPeerRttMs?: number;
}

export interface FailoverIngressConfig {
	/**
	 * CIDRs of the peer nodes. A connection from anywhere else is closed before any byte is
	 * read; an empty list admits nobody. A trusted peer can assert any client IP, so container
	 * or tenant traffic that leaves with the host's address must be kept off this port.
	 */
	trustedSources: string[];
}

// ── Protection ────────────────────────────────────────────────────────────────

export interface RateLimitConfig {
	/** Maximum new connections per second from a single IP. */
	connectionsPerSecond: number;
	/** Token bucket burst size (max allowed burst above steady rate). Default: connectionsPerSecond. */
	burst?: number;
}

/**
 * Sustained (per-minute) token bucket — independent of the per-second `rateLimit` bucket.
 * Both buckets are checked on admission; exhausting either one blocks the connection.
 * Use this to limit total connection volume over longer windows while still allowing
 * short bursts via `rateLimit`.
 */
export interface SustainedRateLimitConfig {
	/** Maximum new connections per minute from a single IP. */
	connectionsPerMinute: number;
	/**
	 * Token bucket burst size. Default: connectionsPerMinute.
	 * Max: 4,294,967 connections (u32 fixed-point limit).
	 */
	burst?: number;
}

/**
 * Penalty box: when an IP exhausts any rate limit, block it for a configurable duration.
 * While penalized, all connections from that IP are rejected outright (no token consumed).
 * If the IP continues to exceed its rate while boxed, the penalty is extended — reset to
 * the full `durationMs` from the moment of continued excess. The penalty expires naturally
 * once the IP stops attacking and the deadline passes.
 */
export interface PenaltyBoxConfig {
	/** Duration in ms an IP is penalized after exhausting any rate limit. Default: 600000 (10 min). */
	durationMs?: number;
}

export interface ProtectionConfig {
	/** Per-second token bucket rate limit per source IP. */
	rateLimit?: RateLimitConfig;
	/**
	 * Per-minute (sustained) token bucket — independent of rateLimit.
	 * Checked in addition to rateLimit; exhausting either blocks the connection.
	 */
	sustained?: SustainedRateLimitConfig;
	/**
	 * Penalty box: block an IP for `durationMs` after any rate limit exhaustion.
	 * Absent = disabled (current behavior: each blocked connection is independent).
	 */
	penaltyBox?: PenaltyBoxConfig;
	/** Maximum simultaneous connections from a single IP. 0 = unlimited. */
	maxConcurrentPerIp?: number;
	/** CIDRs that bypass all protection checks (e.g. trusted internal ranges). */
	allowlist?: string[];
	/** CIDRs that are always blocked. */
	blocklist?: string[];
	/** JA3 MD5 fingerprint hex strings to block (32 hex chars each). */
	ja3Blocklist?: string[];
	/**
	 * JA4 TLS fingerprints to block. Each entry is the full 36-char JA4 string
	 * (t<ver><sni><cc><ec><alpn>_<12hex>_<12hex>); matching is case-insensitive.
	 * Only core JA4 (TLS client fingerprinting, BSD-licensed) is implemented.
	 */
	ja4Blocklist?: string[];
	/** Reject connections whose TLS handshake exceeds this many ms. Default: 10000. */
	tlsHandshakeTimeoutMs?: number;
	/** Reject connections that present no SNI. Default: false. */
	requireSni?: boolean;
}

// ── Listener config ───────────────────────────────────────────────────────────

export interface ListenerConfig {
	host?: string;
	port: number;
	/**
	 * Listener protocol:
	 * - `'tls'` (default) — SNI-routed TLS proxy (termination or passthrough).
	 * - `'http'` — plaintext HTTP/1.1. Requests under `/.well-known/acme-challenge/` are
	 *   proxied to the route matched by the `Host` header; every other request returns
	 *   `301 Moved Permanently` to `https://<host><uri>`. Intended for serving ACME
	 *   HTTP-01 challenges on port 80 alongside the TLS listener on port 443.
	 *   `defaultCert`, `mtls`, and `protection` are ignored in this mode.
	 */
	mode?: 'tls' | 'http';
	/** Fallback certificate for routes that don't specify their own cert. */
	defaultCert?: CertConfig;
	/** Listener-level mTLS config, used when a route doesn't specify its own. */
	mtls?: MtlsConfig;
	/** Global connection cap for this listener. 0 = unlimited. Default: 0. */
	maxConnections?: number;
	/** Drop the connection if it is idle for this many ms. Default: 60000. */
	idleTimeoutMs?: number;
	protection?: ProtectionConfig;
	/**
	 * Make this TLS listener the receiving end of peer failover. Every connection must come from
	 * `trustedSources` and start with a PROXY protocol v2 header, whose source address then
	 * stands in for the client for protection, `allowedSources` and the upstream. Connections
	 * here are never forwarded again, never use a default route, and are closed before the
	 * handshake when the route's local upstream is down or draining.
	 */
	failoverIngress?: FailoverIngressConfig;
}

// ── Top-level proxy config ────────────────────────────────────────────────────

export interface ProxyConfig {
	listeners: ListenerConfig[];
	routes: RouteConfig[];
	/** Number of tokio worker threads. Defaults to available CPU count. */
	workerThreads?: number;
	/**
	 * Per-direction copy buffer size in bytes. Default: 8192. Clamped to [512, 1048576].
	 *
	 * One buffer per direction is allocated per proxied connection and held for its whole life,
	 * transferring or not, so these are a direct multiplier on per-connection memory:
	 * `(client + upstream) x connections`, which is `2 x readBufferSize x connections` only when
	 * both directions use this value. Raising it buys throughput on a handful of bulk streams (replication) and
	 * costs gigabytes on hundreds of thousands of mostly-idle ones (MQTT subscribers). Since the
	 * value is per proxy, tune it per port-set rather than fleet-wide.
	 */
	readBufferSize?: number;
	/** Overrides `readBufferSize` for the client -> upstream direction only. */
	clientReadBufferSize?: number;
	/** Overrides `readBufferSize` for the upstream -> client direction only. */
	upstreamReadBufferSize?: number;
	/**
	 * TCP keepalive for accepted sockets. Omit for the defaults.
	 *
	 * Without it nothing detects a client that disappears without closing: `SO_KEEPALIVE` is off
	 * per socket by default, and the `net.ipv4.tcp_keepalive_*` sysctls govern only sockets that
	 * opted in. The settings are applied to the listening socket and inherited by every socket it
	 * accepts.
	 */
	tcpKeepalive?: TcpKeepaliveConfig;
	/**
	 * Reclaim a connection whose upstream has closed once the surviving client -> upstream
	 * direction has carried nothing for this many ms. Default: 300000. 0 disables the bound.
	 *
	 * `copy_bidirectional` completes only when both directions finish, so without this a client
	 * that never sends its own FIN leaves the socket in FIN-WAIT-2 for the life of the process.
	 * The deadline resets on activity, and only an *upstream* close arms it — a client that
	 * half-closes after its request is still waiting on a response that may legitimately be slow.
	 */
	halfCloseTimeoutMs?: number;
}

/**
 * Probe schedule for accepted sockets. A peer that stops answering is declared dead
 * `idleMs + intervalMs x retries` after the last activity on the connection.
 */
export interface TcpKeepaliveConfig {
	/** Default: true. */
	enabled?: boolean;
	/** Quiet time before the first probe, in ms. Default: 300000. */
	idleMs?: number;
	/** Gap between probes, in ms. Default: 30000. */
	intervalMs?: number;
	/** Unanswered probes before the connection is dropped. Default: 5. */
	retries?: number;
}

// ── Hot-swap config ───────────────────────────────────────────────────────────

/** Protection update for a single listener in a hot-config call. */
export interface ListenerProtectionHotConfig {
	/** Port number of the listener to update. Must match a listener configured at start. */
	port: number;
	protection: ProtectionConfig;
}

/** `trustedSources` update for one failover ingress listener in a hot-config call. */
export interface ListenerFailoverIngressHotConfig {
	/** Port of a listener started with `failoverIngress`. */
	port: number;
	trustedSources: string[];
}

/**
 * Fields that can be updated live without restarting listeners.
 *
 * Hot-swappable: routes (destinations, TLS certs, suspension state) and
 * per-listener protection contents (CIDR lists, JA3 blocklist, rate limits, concurrency
 * caps, handshake timeout, requireSni).
 *
 * Requires restart: bind address, port, idle timeout, half-close timeout, TCP keepalive,
 * worker threads.
 * Protection presence (None↔Some) cannot change via updateConfig() — a listener must be
 * restarted to gain or lose protection. updateConfig() returns an error for ports that have
 * no protection or that match no listener. symphony-server handles none→some/some→none
 * transitions automatically via seamless recreate.
 */
export interface HotConfig {
	routes?: RouteConfig[];
	/**
	 * Per-listener protection updates. Each entry identifies a listener by port and
	 * replaces its entire protection config atomically. Absent = leave unchanged.
	 */
	protection?: ListenerProtectionHotConfig[];
	/**
	 * Per-listener `trustedSources` updates, under the same presence rule as `protection`:
	 * only listeners started with `failoverIngress`.
	 */
	failoverIngress?: ListenerFailoverIngressHotConfig[];
}

// ── Metrics ───────────────────────────────────────────────────────────────────

/** A counter broken out by reason. Every reason is reported, including those still at zero. */
export interface LabeledCount {
	reason: string;
	count: number;
}

export interface ListenerMetrics {
	/** "host:port" — matches the `listener` field on emitted events. */
	address: string;
	mode: 'tls' | 'http';
	activeConnections: number;
	/** Subset of `activeConnections` whose write half to the client is shut down, awaiting its FIN. */
	halfClosedConnections: number;
	accepted: number;
	blocked: number;
	errors: number;
	/** Bytes read from clients (client → upstream). */
	bytesReceived: number;
	/** Bytes written to clients (upstream → client). */
	bytesSent: number;
	blockedByReason: LabeledCount[];
	errorsByReason: LabeledCount[];
	/** Failover ingress: peer load queries answered. */
	loadQueries: number;
}

export interface RouteMetrics {
	/** Configured exact SNI or wildcard pattern, never the client-provided hostname. */
	route: string;
	/** Grouping key from route configuration; empty when not configured. */
	metricsGroup: string;
	activeConnections: number;
	/** Connections that matched this route since process start. */
	connections: number;
	blocked: number;
	errors: number;
	bytesReceived: number;
	bytesSent: number;
	/** Sparse post-route blocks (`source_not_allowed`); zero-valued reasons are omitted. */
	blockedByReason: LabeledCount[];
	/** Sparse post-route failures; zero-valued reasons are omitted. */
	errorsByReason: LabeledCount[];
	/** Present only on routes with `failover`. */
	failover?: RouteFailoverMetrics;
}

export interface RouteFailoverMetrics {
	/** False while every slot of the local upstream (or of its h2 upstream) is refusing. */
	localUp: boolean;
	refusingSlots: number;
	slots: number;
	drain: boolean;
	/** Attempts that replayed the ClientHello to a second or later peer. */
	replays: number;
	/** Connections closed after every candidate peer failed. */
	exhausted: number;
	/** Draining or spilled connections served locally because no peer took them. */
	localFallbacks: number;
	/** Present only on routes with `spill`. */
	spill?: SpillMetrics;
	peers: FailoverPeerMetrics[];
}

export interface SpillMetrics {
	/** Share (0–1) of new connections being spilled now; 0 when spilling is not admitted. */
	fraction: number;
	/** "host:port" of the peer receiving them. */
	target?: string;
	/** Smoothed load (0–1) of the local worker threads; absent when not measurable. */
	localLoad?: number;
}

export interface FailoverPeerMetrics {
	/** "host:port" */
	peer: string;
	/** Connections handed to this peer, because the route was down or draining, once it answered (its first byte arrived). */
	forwarded: number;
	/** Connections spilled to this peer once it answered. */
	spilled: number;
	coolingDown: boolean;
	/** The peer's last load report (0–1) for this route; absent when none is usable. */
	load?: number;
	/** Smoothed connect time of the load query to this peer. */
	rttMs?: number;
	/** Failed attempts by reason (`refused`, `timeout`, `zero_byte_close`, `error`); zero-valued reasons are omitted. */
	failuresByReason: LabeledCount[];
}

export interface ProxyMetrics {
	/** Number of connections currently being proxied. */
	activeConnections: number;
	/** Total connections blocked since start. */
	blockedConnections: number;
	/** Connections currently held waiting for resolveConnection(). */
	pendingSuspended: number;
	/** Suspended connections that were resolved with a route. */
	suspendedResolved: number;
	/** Suspended connections that timed out or were rejected. */
	suspendedUnresolved: number;
	/** Routes in the live table, including the default route. */
	routes: number;
	/**
	 * Routes rejected at build time — a cert failure, protocol/carrier validation failure, invalid
	 * `allowedSources`, or duplicate wildcard — either dropped, or (cert failures only) serving a carried-forward
	 * last-good cert — plus routes serving without failover (or without spill-over) because their `failover`
	 * (or `failover.spill`) policy is invalid.
	 */
	failingRoutes: number;
	/** Per-listener breakdown, in configuration order. */
	listeners: ListenerMetrics[];
	/** Per-configured-route metrics, aggregated across this proxy's listeners. */
	routeMetrics: RouteMetrics[];
}

export interface BlockedIpsInfo {
	/** IPs whose per-second or sustained token buckets are currently depleted. */
	rateLimited: string[];
	/** IPs currently at their maxConcurrentPerIp limit. */
	concurrencyLimited: string[];
	/** The configured static CIDR blocklist entries. */
	cidrBlocklist: string[];
	/** IPs currently in the penalty box (blocked for durationMs after rate-limit exhaustion). */
	penaltyBoxed: string[];
}

// ── Suspended connection ──────────────────────────────────────────────────────

/** Payload of the 'suspended' event. */
export interface SuspendedConnection {
	/** Opaque ID — pass to resolveConnection(). */
	id: string;
	/** The SNI hostname from the ClientHello (empty string if absent). */
	sni: string;
	peerIp: string;
	peerPort: number;
	listener: string;
}

/** Route spec passed to resolveConnection() to forward the held connection. */
export interface ResolveRoute {
	upstream: Upstream;
	terminateTls: boolean;
	cert?: CertConfig;
	mtls?: MtlsConfig;
	/** How the real client IP is forwarded to the upstream. See RouteConfig.sourceAddressHeader. */
	sourceAddressHeader?: 'proxyProtocol' | 'proxyProtocolV2' | 'xForwardedFor' | 'none';
	/** Which client TLS fingerprints to forward downstream. See RouteConfig.forwardFingerprint. */
	forwardFingerprint?: 'ja3' | 'ja4' | 'none' | ('ja3' | 'ja4')[];
	/** Advertise h2 in ALPN for this resolved connection. See RouteConfig.http2. */
	http2?: boolean;
	/** The resolved connection's application protocol. See RouteConfig.protocol. */
	protocol?: 'http' | 'opaque';
	/**
	 * Client addresses this resolution admits; see RouteConfig.allowedSources. Checked in
	 * addition to the suspended route's own list, which has already admitted the client by the
	 * time the 'suspended' event fires. An invalid entry rejects the resolution: the connection
	 * is closed and an 'error' event is emitted.
	 */
	allowedSources?: string[];
}

// ── Event payloads ────────────────────────────────────────────────────────────

export interface BlockedEvent {
	type: 'blocked';
	ip: string;
	reason: string;
	listener: string;
	/** JA3 fingerprint (32-char hex) if the ClientHello was parsed; empty string otherwise. */
	ja3: string;
	/** JA4 fingerprint if the ClientHello was parsed; empty string otherwise. */
	ja4: string;
}

export interface SuspendedEvent extends SuspendedConnection {
	type: 'suspended';
}

export interface ErrorEvent {
	type: 'error';
	message: string;
	listener: string;
}

/** A failover route's local upstream went down or came back (checked every probe interval). */
export interface RouteHealthEvent {
	type: 'routeHealth';
	route: string;
	metricsGroup: string;
	status: 'up' | 'down';
}

export type ProxyEvent = BlockedEvent | SuspendedEvent | ErrorEvent | RouteHealthEvent;
