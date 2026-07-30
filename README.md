# symphony

High-performance TLS termination proxy with SNI-based routing, written in Rust (via [napi-rs](https://napi.rs/)) and exposed as a Node.js native module.

**Designed for Linux** (x64 + arm64, glibc + musl), and will run on MacOS as well. Pre-built binaries are published for all targets.

---

## Overview

symphony sits in front of your services and:

- **Terminates TLS** per route using per-route certificates (falls back to a listener-level default cert)
- **Routes by SNI** hostname — exact matches, wildcard prefixes (`*.example.com`), and a catch-all default
- **Proxies TCP** — either terminating TLS (decrypt + forward plaintext) or passing raw TLS bytes through
- **Balances over Unix Domain Sockets** (UDS) using least-connections weighted by thread CPU utilisation, with optional IP session affinity
- **Limits** routes with per-route token-bucket rate caps to prevent any one route from starving others
- **Protects** connections with per-IP token-bucket rate limiting, concurrency limits, CIDR allowlist/blocklist, JA3 fingerprint blocking, TLS handshake timeout, and SNI-required enforcement
- **Suspends** routes — hold incoming connections and fire an event; your code decides whether to proxy or reject each one
- **Hot-swaps** routes and per-listener protection config (CIDR lists, JA3 blocklist, rate limits, concurrency caps, handshake timeout, requireSni) without restarting or dropping existing connections
- Scales to **~1 million concurrent connections** via `SO_REUSEPORT`, tokio's multi-thread runtime, and lock-free data structures

---

## Installation

```bash
npm install symphony
```

Pre-built binaries are downloaded automatically for your platform during install. No Rust toolchain required.

---

## Quick start

```typescript
import { SymphonyProxy } from 'symphony';
import { readFileSync } from 'node:fs';

const proxy = new SymphonyProxy({
  listeners: [{ port: 443 }],
  routes: [
    {
      sni: 'api.example.com',
      upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: 3000 }],
      terminateTls: true,
      cert: {
        certChain: readFileSync('/etc/ssl/api.pem', 'utf8'),
        privateKey: readFileSync('/etc/ssl/api-key.pem', 'utf8'),
      },
    },
  ],
});

await proxy.start();
console.log('proxy listening on :443');
```

---

## Configuration reference

### `ProxyConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `listeners` | `ListenerConfig[]` | required | One entry per listening address |
| `routes` | `RouteConfig[]` | required | SNI routing table |
| `workerThreads` | `number` | CPU count | Tokio worker threads; also controls `SO_REUSEPORT` socket count per listener |
| `readBufferSize` | `number` | `8192` | Per-direction copy buffer size in bytes, clamped to `[512, 1048576]`. See [Copy buffers and per-connection memory](#copy-buffers-and-per-connection-memory) |
| `clientReadBufferSize` | `number` | `readBufferSize` | Overrides `readBufferSize` for the client→upstream direction only |
| `upstreamReadBufferSize` | `number` | `readBufferSize` | Overrides `readBufferSize` for the upstream→client direction only |

### `ListenerConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `host` | `string` | `'0.0.0.0'` | Bind address |
| `port` | `number` | required | Bind port |
| `mode` | `'tls' \| 'http'` | `'tls'` | Listener protocol. `'http'` serves plaintext for ACME HTTP-01 challenges; everything else gets a 301 to `https://<host><uri>`. See [HTTP listener](#http-listener-acme--https-redirect). |
| `defaultCert` | `CertConfig` | — | Fallback cert for routes without their own cert |
| `mtls` | `MtlsConfig` | — | Listener-level mTLS, used when a route doesn't override it |
| `maxConnections` | `number` | `0` (unlimited) | Drop new connections when active count reaches this |
| `idleTimeoutMs` | `number` | `60000` | Close connections silent for this many ms |
| `protection` | `ProtectionConfig` | — | IP-level protection |

### `RouteConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `sni` | `string` | required | Hostname for exact match, or `'*.suffix'` for wildcard, or `''` for default |
| `upstreams` | `Upstream[]` | required | Destination(s); multiple UDS upstreams are load-balanced |
| `terminateTls` | `boolean` | required | `true` = decrypt TLS; `false` = TCP passthrough |
| `cert` | `CertConfig` | — | Per-route cert, overrides listener `defaultCert` |
| `mtls` | `MtlsConfig` | — | Per-route mTLS, overrides listener `mtls` |
| `suspended` | `boolean` | `false` | Hold connections and emit `'suspended'` events |
| `suspendTimeoutMs` | `number` | `30000` | Drop held connections after this ms if not resolved |
| `maxConnectionsPerSecond` | `number` | — | Route-wide new-connection rate cap (token bucket). Connections are silently dropped when exhausted. |
| `burst` | `number` | `maxConnectionsPerSecond` | Token bucket burst ceiling for the route rate limit |
| `http2` | `boolean` | `false` | Advertise `h2` in ALPN so clients negotiate HTTP/2. Raw H2 frames flow through to the upstream unchanged. Requires `terminateTls: true`. |
| `sourceAddressHeader` | `'proxyProtocol' \| 'proxyProtocolV2' \| 'xForwardedFor' \| 'none'` | `'proxyProtocol'` for UDS, `'none'` for TCP | How the real client IP is forwarded to the upstream. See [Source address forwarding](#source-address-forwarding). |
| `forwardFingerprint` | `'ja3' \| 'ja4' \| 'none'` | `'none'` | Forward the client TLS fingerprint downstream. See [Forwarding the fingerprint](#forwarding-the-fingerprint-downstream). |

### `Upstream`

```typescript
// TCP upstream
{ kind: 'tcp', host: string, port: number }

// Unix Domain Socket upstream
{
  kind: 'uds',
  path: string,
  ipAffinity?: boolean,      // route same-IP connections to same socket
  ipAffinityTtlMs?: number,  // evict affinity entry after this ms idle (default 300000)
  pid?: number,              // Linux PID of the worker process (enables CPU monitoring)
  tid?: number,              // Linux TID of the worker thread (must be set with pid)
}
```

### `CertConfig`

```typescript
{ certChain: string | Buffer, privateKey: string | Buffer }
```

Both fields accept PEM-encoded strings or `Buffer`. The cert chain may include intermediate certificates.

### `MtlsConfig`

```typescript
{ clientCaCert: string | Buffer, requireClientCert?: boolean }
```

`requireClientCert` defaults to `true`. Set to `false` to accept connections without a client cert while still validating those that do present one.

### `ProtectionConfig`

| Field | Type | Default | Description |
|---|---|---|---|
| `rateLimit` | `{ connectionsPerSecond, burst? }` | — | Per-second token bucket per source IP |
| `sustained` | `{ connectionsPerMinute, burst? }` | — | Per-minute token bucket per source IP (independent of `rateLimit`) |
| `penaltyBox` | `{ durationMs? }` | — | Block an IP for `durationMs` after any rate limit exhaustion |
| `maxConcurrentPerIp` | `number` | `0` (unlimited) | Max simultaneous connections per source IP |
| `allowlist` | `string[]` | `[]` | CIDRs that bypass all checks |
| `blocklist` | `string[]` | `[]` | CIDRs that are always blocked |
| `ja3Blocklist` | `string[]` | `[]` | JA3 MD5 hex fingerprints to block (32 chars each) |
| `ja4Blocklist` | `string[]` | `[]` | JA4 TLS fingerprints to block (36-char strings; see [JA4 blocking](#ja4-blocking)) |
| `tlsHandshakeTimeoutMs` | `number` | `10000` | Abort slow TLS handshakes |
| `requireSni` | `boolean` | `false` | Reject connections without an SNI extension |

---

## TLS & mTLS

### Per-route certificates

Each route can have its own certificate. Routes without a cert use the listener's `defaultCert`.

```typescript
const proxy = new SymphonyProxy({
  listeners: [{
    port: 443,
    defaultCert: { certChain: wildcardCert, privateKey: wildcardKey },
  }],
  routes: [
    // Uses its own cert
    { sni: 'special.example.com', cert: { certChain: specialCert, privateKey: specialKey }, ... },
    // Falls back to listener defaultCert
    { sni: '*.example.com', ... },
  ],
});
```

### mTLS

```typescript
const proxy = new SymphonyProxy({
  listeners: [{
    port: 443,
    mtls: { clientCaCert: readFileSync('ca.pem', 'utf8'), requireClientCert: true },
  }],
  routes: [
    {
      sni: 'internal.example.com',
      terminateTls: true,
      cert: { certChain, privateKey },
      // Inherits listener mTLS; or override per-route:
      // mtls: { clientCaCert: ..., requireClientCert: false },
    },
  ],
});
```

### TLS passthrough

Set `terminateTls: false` to forward raw TLS bytes to the upstream without decryption. No cert needed.

```typescript
{ sni: 'passthrough.example.com', terminateTls: false, upstreams: [{ kind: 'tcp', host: '10.0.0.5', port: 443 }] }
```

---

## Routing

Routes are checked in order: **exact match** → **wildcard suffix** → **default** (empty `sni`).

```typescript
routes: [
  { sni: 'api.example.com', ... },        // exact
  { sni: '*.example.com', ... },          // matches foo.example.com, bar.example.com
  { sni: '', ... },                        // catch-all default
]
```

### Suspended routes

Use suspended routes to inspect or authorize connections before proxying them:

```typescript
proxy.on('suspended', async (conn) => {
  // conn.id, conn.sni, conn.peerIp, conn.peerPort, conn.listener
  const allowed = await checkAuthority(conn);

  if (allowed) {
    proxy.resolveConnection(conn.id, {
      upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: 3000 }],
      terminateTls: false,
    });
  } else {
    proxy.resolveConnection(conn.id, null); // reject — TCP close
  }
});

// Route declared as suspended
{ sni: 'gated.example.com', suspended: true, upstreams: [], terminateTls: true, cert: { ... } }
```

Connections not resolved within `suspendTimeoutMs` are dropped automatically. Calling `resolveConnection` with an unknown or already-expired ID is a no-op.

---

## HTTP listener (ACME + HTTPS redirect)

Setting `mode: 'http'` on a listener switches it from the default SNI-routed TLS proxy to a plaintext HTTP/1.1 handler intended for port 80. It serves two purposes:

* **ACME HTTP-01 challenges** — requests under `/.well-known/acme-challenge/` are proxied to the route matched by the `Host` header (using the same wildcard rules as SNI matching). The upstream is the route's first upstream, so a single route table covers both `:443` TLS routing and `:80` ACME proxying.
* **HTTPS redirect** — every other request gets `HTTP/1.1 301 Moved Permanently` with `Location: https://<host><request-target>`.

Requests with no `Host` header return `400 Bad Request`. ACME requests for hosts with no matching route return `404 Not Found`.

```typescript
new SymphonyProxy({
  listeners: [
    { host: '0.0.0.0', port: 443 },                         // TLS proxy
    { host: '0.0.0.0', port: 80, mode: 'http' },            // ACME + redirect
  ],
  routes: [
    {
      sni: 'api.example.com',
      upstreams: [{ kind: 'uds', path: '/var/harper/api.sock' }],
      terminateTls: true,
      cert: { certChain, privateKey },
    },
  ],
});
```

`defaultCert`, `mtls`, and `protection` on an HTTP-mode listener are ignored.

---

## UDS load balancing

Provide multiple `uds` upstreams for a route. symphony picks the socket with the lowest score, where score is:

```
score = active_connections × 1000 + cpu_utilisation_permille
```

Active connections are the primary factor; CPU utilisation (0–1000, representing 0–100%) is a tiebreaker that steers new connections away from overloaded threads when connection counts are equal.

```typescript
upstreams: [
  { kind: 'uds', path: '/run/app/worker-0.sock' },
  { kind: 'uds', path: '/run/app/worker-1.sock' },
  { kind: 'uds', path: '/run/app/worker-2.sock' },
]
```

### IP session affinity

Add `ipAffinity: true` to any UDS upstream entry to pin source IPs to the same socket:

```typescript
upstreams: [
  { kind: 'uds', path: '/run/app/worker-0.sock', ipAffinity: true, ipAffinityTtlMs: 300000 },
  { kind: 'uds', path: '/run/app/worker-1.sock', ipAffinity: true },
]
```

The same `ipAffinity` / `ipAffinityTtlMs` values apply to all sockets in the set (values from the first entry are used for the shared balancer).

### Thread CPU utilisation monitoring

When each UDS upstream serves a known worker thread, symphony can read its CPU utilisation from `/proc/{pid}/task/{tid}/stat` and incorporate it into socket selection:

```typescript
upstreams: [
  { kind: 'uds', path: '/run/app/worker-0.sock', pid: 12345, tid: 12346 },
  { kind: 'uds', path: '/run/app/worker-1.sock', pid: 12345, tid: 12347 },
  { kind: 'uds', path: '/run/app/worker-2.sock', pid: 12345, tid: 12348 },
]
```

Symphony samples `/proc/{pid}/task/{tid}/stat` every 250 ms and computes the thread's CPU utilisation over the interval. Sockets without `pid`/`tid` keep a CPU score of 0 and fall back to pure least-connections. Sampling stops gracefully when `pid` is gone (process exit, crash) — those slots simply keep their last measured value.

---

## Per-route rate limiting

Use `maxConnectionsPerSecond` on a route to cap the rate of new connections accepted for that route, independent of source IP. This prevents a single busy route from starving other routes under high load:

```typescript
routes: [
  {
    sni: 'api.example.com',
    maxConnectionsPerSecond: 500,  // route-wide cap; burst defaults to this value
    burst: 1000,                   // allow short bursts up to 1000 conn/s
    upstreams: [{ kind: 'uds', path: '/run/app/api.sock' }],
    terminateTls: true,
    cert: { certChain, privateKey },
  },
  {
    sni: 'admin.example.com',
    maxConnectionsPerSecond: 20,
    upstreams: [{ kind: 'uds', path: '/run/app/admin.sock' }],
    terminateTls: true,
    cert: { certChain, privateKey },
  },
]
```

Connections that exceed the limit are silently dropped (TCP RST). This is a global token bucket per route — not per IP. For per-IP rate limiting use `protection.rateLimit`.

---

## Source address forwarding

Use `sourceAddressHeader` on a route to control how the real client IP is communicated to the upstream. The PROXY protocol carriers work whether or not TLS is terminated (they prefix the connection); `'xForwardedFor'` requires `terminateTls: true` and a plaintext HTTP/1 upstream, since it rewrites the HTTP request.

| Value | Behaviour |
|---|---|
| `'proxyProtocol'` | Sends a PROXY protocol v1 (text) header (`PROXY TCP4 <src-ip> <dst-ip> <src-port> 0\r\n`) before any application data. Default for UDS upstreams. |
| `'proxyProtocolV2'` | Sends a PROXY protocol v2 (binary) header before any application data. v2 adds a TLV section — the carrier for `forwardFingerprint` below and for [mTLS client cert forwarding](#forwarding-mtls-client-certificates). Keep it opt-in: the consumer must speak v2 (nginx/HAProxy do; Harper core's UDS reader parses v1 only before Harper 5.2). |
| `'xForwardedFor'` | Reads the first chunk of the HTTP request, inserts an `X-Forwarded-For` header after the request line, then copies the rest verbatim. No per-request parsing overhead for keep-alive connections. Default for TCP upstreams (disabled). |
| `'none'` | Does not forward source address information. Default for TCP upstreams. |

### PROXY protocol (default for UDS)

Most backends that consume PROXY protocol (nginx, HAProxy, HarperDB) read the header once per connection before parsing application data.

```typescript
{
  sni: 'api.example.com',
  upstreams: [{ kind: 'uds', path: '/run/app/worker.sock' }],
  terminateTls: true,
  cert: { certChain, privateKey },
  // sourceAddressHeader: 'proxyProtocol',  // this is already the default for UDS
}
```

### X-Forwarded-For (for Bun and other HTTP backends)

Bun's built-in HTTP server does not support PROXY protocol. Use `'xForwardedFor'` instead — symphony injects the header into the first HTTP request of each connection:

```typescript
{
  sni: 'app.example.com',
  upstreams: [{ kind: 'uds', path: '/run/bun/worker.sock' }],
  terminateTls: true,
  cert: { certChain, privateKey },
  sourceAddressHeader: 'xForwardedFor',
}
```

In your Bun server:

```typescript
Bun.serve({
  unix: '/run/bun/worker.sock',
  fetch(req) {
    const clientIp = req.headers.get('x-forwarded-for');
    // ...
  },
});
```

### Forwarding the fingerprint downstream

symphony computes the client's JA3/JA4 fingerprint from the ClientHello (the same value used for `ja3Blocklist`/`ja4Blocklist`). Set `forwardFingerprint` to also hand it to the upstream, so a backend behind symphony can make its own bot/abuse decisions on it.

| `forwardFingerprint` | Value forwarded |
|---|---|
| `'ja3'` | The JA3 MD5 hex (32 chars) |
| `'ja4'` | The JA4 fingerprint |
| `'none'` (default) | Nothing forwarded |

The **carrier depends on `sourceAddressHeader`**:

- With `'proxyProtocolV2'`, the fingerprint rides a PROXY v2 **TLV** — type `0xE0` for JA3, `0xE1` for JA4 (in HAProxy's `0xE0–0xEF` private range). This works even in passthrough (`terminateTls: false`), since the header prefixes the raw TLS bytes.
- Otherwise, symphony injects an **`X-JA3` / `X-JA4` HTTP header**. This requires a plaintext HTTP/1 upstream (`terminateTls: true` and not `http2`); it is skipped for passthrough or HTTP/2 upstreams (use `'proxyProtocolV2'` there). Any client-supplied `X-JA3`/`X-JA4` is stripped so the injected value is authoritative and can't be spoofed.

A config that requests `forwardFingerprint` with no viable carrier — passthrough (`terminateTls: false`) without `sourceAddressHeader: 'proxyProtocolV2'`, where there's neither an HTTP request to inject a header into nor a v2 TLV — logs a startup warning rather than silently dropping the signal.

```typescript
// TLV carrier — works for any upstream that speaks PROXY v2, including passthrough
{
  sni: 'app.example.com',
  upstreams: [{ kind: 'tcp', host: '10.0.0.5', port: 8080 }],
  terminateTls: true,
  cert: { certChain, privateKey },
  sourceAddressHeader: 'proxyProtocolV2',
  forwardFingerprint: 'ja4',
}

// HTTP-header carrier — for HTTP/1 backends that read request headers
{
  sni: 'app.example.com',
  upstreams: [{ kind: 'uds', path: '/run/app/worker.sock' }],
  terminateTls: true,
  cert: { certChain, privateKey },
  sourceAddressHeader: 'xForwardedFor',
  forwardFingerprint: 'ja3', // upstream reads X-JA3 alongside X-Forwarded-For
}
```

### Forwarding mTLS client certificates

When symphony terminates TLS on a route with `mtls` configured, the verified client
certificate would normally be invisible to the upstream. With
`sourceAddressHeader: 'proxyProtocolV2'` and `terminateTls: true`, the v2 TLV section
carries the connection's TLS facts, once per connection, before any application data:

| TLV | Type | Content |
|---|---|---|
| ALPN | `0x01` | Negotiated ALPN protocol (e.g. `h2`) |
| Authority | `0x02` | SNI hostname from the ClientHello |
| SSL | `0x20` | `client` bit field (`0x01` = TLS, `0x02` = client cert presented on this connection), `verify` (u32 BE, `0` only for a verified cert), and sub-TLVs `0x21` (TLS version) and `0x23` (cipher suite) |
| Client cert chain | `0xE2` (custom range, after JA3 `0xE0` / JA4 `0xE1`) | One TLV per certificate, DER-encoded, leaf first |

```typescript
{
  sni: 'api.example.com',
  upstreams: [{ kind: 'uds', path: '/run/app/worker.sock' }],
  terminateTls: true,
  cert: { certChain, privateKey },
  mtls: { clientCaCert, requireClientCert: true },
  sourceAddressHeader: 'proxyProtocolV2',
}
```

A certificate chain is only forwarded when the `mtls` verifier accepted it — rustls
aborts the handshake otherwise — so an upstream receiving a `0xE2` TLV over a trusted
(e.g. UDS) link can treat it as a verified client identity. A pathological chain that
cannot fit the v2 header's 16-bit length budget is omitted with a warning (the SSL TLV
still signals that a verified cert was presented). On passthrough routes
(`terminateTls: false`) the TLS facts are unavailable; the header carries the source
address, SNI authority, and any configured fingerprint TLV.

---

## Protection

### Recommended starting values for public-facing deployments

```typescript
protection: {
  rateLimit: { connectionsPerSecond: 50, burst: 100 },
  sustained: { connectionsPerMinute: 300, burst: 300 },
  penaltyBox: { durationMs: 600_000 }, // 10 minutes
  maxConcurrentPerIp: 200,
  allowlist: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
  requireSni: true,
  tlsHandshakeTimeoutMs: 5000,
}
```

### Sustained rate limits

Use `sustained` to enforce a per-minute cap that is independent of the per-second `rateLimit` bucket. Both buckets are checked on every connection; exhausting either one blocks the connection. This lets you allow short bursts while still capping total volume over longer windows:

```typescript
protection: {
  rateLimit: { connectionsPerSecond: 50, burst: 200 }, // allow short bursts
  sustained: { connectionsPerMinute: 600, burst: 600 }, // but cap at 10/s long-term
}
```

### Penalty box

When `penaltyBox` is configured, exhausting any rate limit places the source IP in a penalty box for `durationMs` (default 10 minutes). While penalized, all connections from that IP are rejected outright without touching the token buckets — protecting the proxy from re-assembling per-connection state under a sustained attack.

**Extension semantics:** while an IP is boxed, symphony still debits its token buckets on each connection attempt (to measure whether the attack is continuing). If a bucket is exhausted (the IP is still sending at the excess rate), the penalty deadline is reset to `now + durationMs` — effectively extending the penalty by a full `durationMs` from the moment of continued excess. If the IP stops attacking, the buckets refill and debits succeed; the deadline is not extended, so the IP is readmitted once the original deadline expires.

```typescript
protection: {
  rateLimit: { connectionsPerSecond: 50, burst: 100 },
  penaltyBox: { durationMs: 600_000 }, // 10 minutes (default)
}
```

Blocked events from penalized IPs have `reason: 'penalty_boxed'`. They appear under `penaltyBoxed` in `blockedIps()`:

```typescript
const info = proxy.blockedIps();
// info.penaltyBoxed — IPs currently in the penalty box
```

Penalty state is stored on per-IP runtime state and survives a configuration hot-swap. `penaltyBox` can be added or removed via `updateConfig` without restarting.

**Hot-swap note on active deadlines:** changing `durationMs` via `updateConfig` affects new penalty stamps immediately, but IPs already in the box retain their current deadline until it expires or is re-stamped by a continued rate-limit hit. There is no retroactive recalculation of existing deadlines.

### JA3 blocking

JA3 fingerprints the TLS ClientHello by hashing a canonical string of the version, cipher suites, extensions, elliptic curves, and EC point formats using MD5. That MD5 is by specification, not a security claim — it allows lists of known-bad fingerprints to be compared cheaply. Collect JA3 fingerprints from your logs (available in the `blocked` event `ja3` field) and add known-bad clients:

```typescript
ja3Blocklist: [
  'e7d705a3286e19ea42f587b344ee6865', // example known-bad scanner
]
```

**Limitation:** Chrome and other modern browsers randomize the order of ClientHello extensions on each connection, so a single browser can produce many different JA3 hashes. This makes per-browser JA3 blocking unreliable. Use `ja4Blocklist` where extension-order randomization is a concern.

**Upgrade note:** earlier versions filtered only one of the 16 GREASE values when computing JA3, so hashes for clients that send other GREASE values (e.g. Chrome) were nonstandard and unstable. JA3 values collected from earlier symphony versions may no longer match and should be re-collected.

### JA4 blocking

JA4 is the randomization-resistant successor to JA3. It sorts the cipher and extension lists before hashing, so it produces a stable fingerprint regardless of ClientHello field ordering. Fingerprints are 36-char lowercase ASCII strings in the form `t<ver><sni><cc><ec><alpn>_<sha256/12>_<sha256/12>`.

Collect JA4 values from the `blocked` event `ja4` field and configure them:

```typescript
ja4Blocklist: [
  't13d1516h2_8daaf6152771_b186095e22b6', // example Chrome fingerprint
]
```

Matching is case-insensitive. JA4 fingerprints are always emitted as lowercase. A blocklist
entry that isn't a structurally valid JA4 (or JA3) string is rejected at construction rather
than silently installed as an entry that could never match.

**Fail-closed reassembly:** when a `ja3Blocklist` or `ja4Blocklist` is configured, symphony
reassembles the full ClientHello (bounded by size and a short timeout) before fingerprinting.
A connection whose ClientHello can't be fully reassembled — e.g. a client that fragments it to
expose SNI while withholding later extensions — is **blocked** (`blocked` reason
`incomplete_handshake`) rather than allowed on a partial/empty fingerprint. Without enforcement
configured, fingerprinting stays best-effort and an incomplete hello is not blocked.

**License scope:** Symphony implements **core JA4** (TLS client fingerprinting) only. Core JA4 is BSD-licensed. The JA4+ suite of variants (JA4S, JA4H, JA4SSH, etc.) carries a separate FoxIO proprietary license and is **not implemented** here.

### Hot-swapping protection config

Protection config is per-listener and fully hot-swappable via `updateConfig`. Push a new config atomically to each listener by port — no restart needed, in-flight connections are unaffected:

```typescript
// Block a new CIDR range without restarting
proxy.updateConfig({
  protection: [
    {
      port: 443,
      protection: {
        blocklist: ['198.51.100.0/24'],  // added under attack
        rateLimit: { connectionsPerSecond: 50, burst: 100 },
        requireSni: true,
      },
    },
  ],
});
```

The entire `ProtectionConfig` is replaced atomically (one pointer swap). Any field not included in the new config reverts to its default. Existing per-IP rate-limit token buckets are preserved across a swap; if burst decreases, tokens are capped at the new ceiling on the next refill — no underflow.

**Transitions (none→some, some→none):** when using `symphony-server`, adding or removing a `protection` block in the config file triggers a seamless proxy recreate via SO_REUSEPORT — no bind gap, existing connections unaffected. Only contents-only changes (same presence, different CIDR/rate/etc.) stay on the pure hot-swap path. When calling `updateConfig()` directly, a listener that was started without protection cannot gain it and returns an error; restart the listener to change protection presence.

---

## Security & compliance

For deployment hardening and security-questionnaire guidance — private key file
handling and rotation, protecting the (hot-reloaded) config file with restrictive
permissions and file-integrity monitoring, why an MD5 dependency appears (JA3
fingerprinting, not a cryptographic use), the current TLS parameters and FIPS/PCI
attestation roadmap, and the shared-responsibility split for DDoS — see
[SECURITY.md](./SECURITY.md).

---

## Metrics & monitoring

### In-process (`proxy.metrics()`)

```typescript
const m = proxy.metrics();
// Proxy-wide
// m.activeConnections     — connections being proxied right now
// m.blockedConnections    — total rejected since start (protection + maxConnections)
// m.pendingSuspended      — connections held waiting for resolveConnection()
// m.suspendedResolved     — suspended connections that were resolved with a route
// m.suspendedUnresolved   — suspended connections that timed out or were rejected
// m.routes                — routes in the live table, including the default route
// m.failingRoutes         — routes whose cert failed to build (see "Per-route certificates")

// Per listener, in configuration order
for (const l of m.listeners) {
  // l.address, l.mode ('tls' | 'http')
  // l.activeConnections, l.accepted
  // l.bytesReceived — bytes read from clients   (client → upstream)
  // l.bytesSent     — bytes written to clients  (upstream → client)
  //   Counted where the proxy sees the bytes. On a terminated-TLS route that is the plaintext
  //   stream, and the handshake — which precedes the counter — is excluded. On a passthrough
  //   route the proxy has no plaintext view and forwards wire bytes, so the handshake records
  //   are part of the stream and are counted.
  // l.blockedByReason — [{ reason: 'rate_limited', count: 12 }, ...]
  // l.errorsByReason  — [{ reason: 'upstream_connect', count: 3 }, ...]
}

const blocked = proxy.blockedIps();
// blocked.rateLimited — IPs with a depleted per-second or sustained token bucket
// blocked.concurrencyLimited — IPs at their maxConcurrentPerIp limit
// blocked.cidrBlocklist — the configured static CIDR blocklist
// blocked.penaltyBoxed — IPs currently in the penalty box
```

Every reason is reported on every call, including reasons still at zero, so a dashboard series
exists before the first incident rather than appearing mid-outage. `l.blocked` / `l.errors` are
summed from the very reason values reported alongside them, and `m.blockedConnections` from the
listener values in the same snapshot — so a reading taken mid-traffic is internally consistent
rather than only adding up while the proxy is idle.

**Block reasons:** `max_connections`, `cidr_blocked`, `ja3_blocked`, `ja4_blocked`,
`incomplete_handshake`, `no_sni`, `rate_limited`, `too_many_connections`, `penalty_boxed`.

**Error reasons:** `no_route`, `route_rate_limited`, `suspend_unresolved`, `tls_handshake`,
`tls_missing_cert`, `upstream_connect`, `idle_timeout`, `stream`, `http_header`.

> `idle_timeout` counts terminations by `idleTimeoutMs`, which today is a *total duration* cap
> rather than an idleness one — see [#34](https://github.com/HarperFast/symphony/issues/34). Busy
> long-lived connections land in this bucket, not just quiet ones.

### Out-of-process (`symphony-server` admin endpoint)

When symphony runs as its own process there is no JS API to call, so the server bin can expose
the same numbers over HTTP. Add an `admin` block to the config file:

```json
{
  "version": 1,
  "admin": {
    "socketPath": "/run/symphony/admin.sock",
    "socketMode": 432,
    "port": 9095,
    "host": "127.0.0.1"
  },
  "proxies": [ ... ]
}
```

Both bindings are optional; give either or both. Omit the `admin` block entirely and nothing is
exposed. `socketPath` may be relative to the config file's directory, and is chmodded to
`socketMode` (default `0o660`) after bind. `host` defaults to `127.0.0.1` — metrics carry no
tenant identifiers, but there is still no reason to publish them off-box.

| Route | Response |
|---|---|
| `GET /metrics` | Prometheus text exposition (v0.0.4) |
| `GET /metrics.json` | the same snapshot as JSON |
| `GET /health` | `{ ok, pid, version, ports }` |

```
$ curl --unix-socket /run/symphony/admin.sock http://localhost/metrics
# HELP symphony_build_info Always 1; the version is carried in the label.
# TYPE symphony_build_info gauge
symphony_build_info{version="0.5.0"} 1
...
symphony_listener_accepted_total{proxy="80,443",listener="0.0.0.0:443",mode="tls"} 148213
symphony_listener_blocked_total{proxy="80,443",listener="0.0.0.0:443",mode="tls",reason="rate_limited"} 27
symphony_listener_errors_total{proxy="80,443",listener="0.0.0.0:443",mode="tls",reason="upstream_connect"} 4
```

The `proxy` label is the port-set of the proxy entry the listener belongs to (each config entry
gets its own route table). Blocked and error counts are only ever emitted with their `reason`
label — the labelled series sum to the total, so use `sum without(reason)` rather than looking
for a separate unlabelled metric. Likewise the proxy-wide active-connection gauge is
`sum without(listener) (symphony_listener_active_connections)`.

The endpoint is strictly read-only and best-effort: it never blocks proxying, and a bind failure
is logged and retried every 5s rather than aborting startup. That matters during a version
upgrade, where the incumbent still holds the socket while the replacement is already serving
traffic through `SO_REUSEPORT` — the successor picks up the admin endpoint once the old process
exits. A socket file left behind by a `SIGKILL`ed process is reclaimed automatically, but only
after a connect probe proves nobody is listening on it.

The Prometheus renderer is internal to the standalone server and is not exported from the
package root: a snapshot carries that process's pid, timestamps, and port-set grouping, which an
embedded consumer would have to synthesise. An embedded proxy has `proxy.metrics()` directly. If
a caller genuinely needs Prometheus text from an embedded proxy, open an issue — the right shape
is a `ProxyMetrics`-based renderer, not this one.

---

## Hot config updates

```typescript
// Replace the entire route table atomically — in-flight connections are unaffected.
proxy.updateConfig({
  routes: newRoutes,
});
```

**What can be hot-swapped:** routes (destinations, TLS certs, suspension state) and per-listener protection (CIDR allowlist/blocklist, JA3 blocklist, rate limits, sustained rate limits, penalty box, concurrency caps, handshake timeout, requireSni).

**What requires a restart:** bind address, port, idle timeout, worker threads. When calling `updateConfig()` directly, protection presence (None↔Some) cannot change at runtime — the listener must be restarted. The `symphony-server` bin handles this automatically via seamless recreate.

---

## Building from source

Requirements: Rust stable (1.70+), Node.js 18+, `@napi-rs/cli`.

```bash
npm install
npm run build:debug    # builds a dev .node file
npm run build          # release build (LTO, stripped)
```

### Cross-compilation

Use the napi-rs Docker images (same ones used in CI):

```bash
# x64 musl (Alpine)
docker run --rm -v $(pwd):/build -w /build \
  ghcr.io/napi-rs/napi-rs/nodejs-rust:lts-alpine \
  npm run build -- --target x86_64-unknown-linux-musl

# arm64 glibc
docker run --rm -v $(pwd):/build -w /build \
  ghcr.io/napi-rs/napi-rs/nodejs-rust:lts-debian-aarch64 \
  npm run build -- --target aarch64-unknown-linux-gnu
```

---

## Copy buffers and per-connection memory

`readBufferSize` (and its per-direction overrides) is a *maximum*, not a permanent allocation. Each
direction starts at a small fixed floor (1 KiB total across both directions) and escalates to the
configured maximum only once it observes a sustained burst — two consecutive reads that fill the
current buffer — dropping straight back to the floor once the direction actually parks with nothing
left to write, not on every single under-capacity read (that would reallocate a connection that is
still continuously active but simply has variably-sized traffic). So only the memory *above* that
floor scales with concurrently bursting transfers; the 1 KiB/connection floor itself still scales
with connection count, same as before. A million idle MQTT subscribers cost about 0.95 GiB in floors
(1 KiB × 1,000,000 connections), not `readBufferSize × 2 × 1,000,000`.

```
worst-case buffer bytes = (clientReadBufferSize + upstreamReadBufferSize) × connections bursting right now
```

That's the ceiling if every connection happened to be mid-burst simultaneously — a useful number to
size against, but not the steady-state cost, which sits near the 1 KiB/connection floor regardless of
`readBufferSize`. Each unset override falls back to `readBufferSize`, so with symmetric sizing the
ceiling is `2 × readBufferSize × connections bursting right now`. At the 8192-byte default that is 16
KiB per bursting connection. The asymmetric MQTT setting recommended below is `1024 + 4096` = 5 KiB
per bursting connection, which is where the general form matters.
The knob still bounds how large a *single* transfer's buffer may grow, and the right bound is the
opposite for the two shapes of traffic symphony carries:

| Traffic | Connections | Payloads | Suggested |
|---|---|---|---|
| Native MQTT (`8883`) | 100k–1M | hundreds of bytes | `clientReadBufferSize: 1024`, `upstreamReadBufferSize: 4096` |
| HTTPS (`443`) | thousands | mixed | leave at the default |
| Operations API (`9925`) | tens | can be large | leave at the default |
| Replication (`9933`) | ~6 | bulk streams | leave, or raise — 64 KiB across 6 connections bursting at once is 768 KB total |

MQTT is worth splitting by direction: after `SUBSCRIBE` a client sends almost nothing but `PINGREQ`,
while the broker carries the whole fan-out. `1024`/`4096` bounds a bursting connection to 5 KiB
against the default's 16 KiB ceiling, and buys more downstream headroom than a symmetric 2048 would.

Going small costs CPU, not correctness: a payload larger than the buffer is simply copied in more
iterations, and a connection that keeps bursting re-escalates after two full reads. On a
TLS-terminating listener those extra iterations are not even syscalls, since the reads come out of
rustls's already-decrypted buffer.

Two limits on where these settings apply:

- **Only the plain proxying path.** A route that injects HTTP headers (`sourceAddressHeader:
  'xForwardedFor'`, or a header-carried `forwardFingerprint`) is framed per-request by
  `proxy_http1_rewriting`, which uses its own fixed 8 KiB buffers — the same size as the default
  here, so the default is unaffected, but a raised or lowered value has no effect on those routes.
  PROXY-protocol routes, including every UDS route, take the plain path and are governed normally.
- **A config reload cannot change these.** They are frozen when the proxy is constructed, so
  changing one makes `symphony-server` recreate the proxy rather than hot-swap it. `SO_REUSEPORT`
  means there is no *bind* gap, but established connections on the old proxy are **not** drained —
  `stop()` waits 100 ms and connection tasks are detached — so they are all dropped. On a
  high-connection-count listener, treat a buffer-size edit as a reconnect event, not a live tune.

> **Upgrading:** before this setting was applied to the copy loop, `readBufferSize` had no effect —
> every connection got a fixed 8 KiB per direction regardless of what the config said (held for the
> connection's whole life, not escalating/shrinking), and the default documented here was `65536`. A
> config that leaves it unset is unaffected. A config that *sets* it explicitly now gets what it
> asked for as a per-transfer ceiling, so a value copied from the old documented default raises that
> ceiling to 128 KiB per bursting connection instead of 16 KiB. Drop or remove such a value before
> upgrading a high-connection-count deployment.

Two caveats when sizing a node from this:

- Buffers are one term, not the whole per-connection cost. A TLS-terminating listener also carries
  rustls session state per connection, plus kernel socket memory (bounded in aggregate by
  `net.ipv4.tcp_mem`). Measure the actual slope — `activeConnections` from the admin endpoint
  against process RSS — before deciding a connection target is reachable.
- Buffer memory is not what caps connection count. File descriptors (2 per proxied connection,
  against `RLIMIT_NOFILE`) and `nf_conntrack_max` bind first; see
  [Linux kernel tuning](#linux-kernel-tuning).

## Linux kernel tuning

To reach ~1 million concurrent connections, the following system settings are required.

### File descriptor limits

```bash
# Per-process (set before starting Node)
ulimit -n 2097152

# System-wide persistent — /etc/security/limits.conf
*  soft  nofile  2097152
*  hard  nofile  2097152
```

symphony attempts to raise `RLIMIT_NOFILE` automatically at startup (to `2 × maxConnections + 1024`), but the hard limit must be raised by the OS first.

### Kernel networking

```bash
# /etc/sysctl.d/99-symphony.conf

# TCP connection tracking
net.ipv4.ip_local_port_range = 1024 65535
net.ipv4.tcp_tw_reuse = 1

# Socket buffers (tune to your bandwidth)
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# Accept queue depth per socket
net.core.somaxconn = 65535
net.ipv4.tcp_max_syn_backlog = 65535

# Max open files system-wide
fs.file-max = 4194304
```

Apply with:

```bash
sudo sysctl --system
```

### musl note

On musl-libc systems (Alpine), the hard `RLIMIT_NOFILE` is often capped at 1048576 rather than the glibc default of 1073741816. symphony will log a warning if the desired limit exceeds the hard limit and fall back to the hard limit.
