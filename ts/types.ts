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
	 * left-label (e.g. "*.example.com"). Use "" for the default/catch-all route.
	 */
	sni: string;
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
	 *   data. v2 carries a TLV section, which is the carrier for `forwardFingerprint`.
	 *   Keep opt-in: consumers must speak v2 (HAProxy/nginx do; Harper core's UDS reader
	 *   currently parses v1 only).
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
	 * - `'none'` (default) — do not forward.
	 *
	 * Carrier: a PROXY v2 TLV when `sourceAddressHeader` is `'proxyProtocolV2'` (works in
	 * passthrough too, since it prefixes the raw TLS bytes); otherwise an injected
	 * `X-JA3` / `X-JA4` HTTP header, which requires a plaintext HTTP/1 upstream
	 * (`terminateTls: true` and not `http2`) — it is skipped otherwise. Any client-supplied
	 * `X-JA3` / `X-JA4` is stripped so the injected value is authoritative.
	 */
	forwardFingerprint?: 'ja3' | 'ja4' | 'none';
	/**
	 * Advertise HTTP/2 (`h2`) in the TLS ALPN extension so clients can negotiate
	 * HTTP/2. When true, symphony declares `['h2', 'http/1.1']` in ALPN and the
	 * upstream receives raw HTTP/2 frames over the plaintext socket — no translation.
	 * Requires `terminateTls: true`. Default: false.
	 */
	http2?: boolean;
}

// ── Protection ────────────────────────────────────────────────────────────────

export interface RateLimitConfig {
	/** Maximum new connections per second from a single IP. */
	connectionsPerSecond: number;
	/** Token bucket burst size (max allowed burst above steady rate). Default: connectionsPerSecond. */
	burst?: number;
}

export interface ProtectionConfig {
	rateLimit?: RateLimitConfig;
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
}

// ── Top-level proxy config ────────────────────────────────────────────────────

export interface ProxyConfig {
	listeners: ListenerConfig[];
	routes: RouteConfig[];
	/** Number of tokio worker threads. Defaults to available CPU count. */
	workerThreads?: number;
	/** Internal read buffer size in bytes. Default: 65536. */
	readBufferSize?: number;
}

// ── Hot-swap config ───────────────────────────────────────────────────────────

/** Fields that can be updated live without restarting listeners. */
export interface HotConfig {
	routes?: RouteConfig[];
}

// ── Metrics ───────────────────────────────────────────────────────────────────

export interface ProxyMetrics {
	/** Number of connections currently being proxied. */
	activeConnections: number;
	/** Total connections blocked since start. */
	blockedConnections: number;
	/** Connections currently held waiting for resolveConnection(). */
	pendingSuspended: number;
}

export interface BlockedIpsInfo {
	/** IPs whose token buckets are currently depleted. */
	rateLimited: string[];
	/** IPs currently at their maxConcurrentPerIp limit. */
	concurrencyLimited: string[];
	/** The configured static CIDR blocklist entries. */
	cidrBlocklist: string[];
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
	/** Which client TLS fingerprint to forward downstream. See RouteConfig.forwardFingerprint. */
	forwardFingerprint?: 'ja3' | 'ja4' | 'none';
	/** Advertise h2 in ALPN for this resolved connection. See RouteConfig.http2. */
	http2?: boolean;
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

export type ProxyEvent = BlockedEvent | SuspendedEvent | ErrorEvent;
