# CLAUDE.md — AI/contributor context for symphony

This file is the primary entry point for any AI assistant working on this codebase.

---

## Architecture

symphony is a **napi-rs cdylib** loaded by Node.js. The tokio multi-thread runtime is embedded via napi's `tokio_rt` feature. The JS API is a thin `EventEmitter` wrapper (`ts/proxy.ts: SymphonyProxy`) over the napi class (`src/proxy.rs: SymphonyProxyWrap`).

### Standalone server (`ts/server.ts` → `dist/server.js`, the `symphony-server` bin)

For consumers that want symphony as its own OS process rather than embedded in their Node app, the package ships a `symphony-server` bin. It reads a JSON config file (`{ version, proxies: [{ listeners, routes }] }` — one entry per port-set, since the route table is per-proxy), constructs a `SymphonyProxy` per entry, and **watches the config file** to hot-reload (route change → `updateConfig`; listener change → recreate that proxy). Cert material may be given inline (`certChain`/`privateKey`) or by path (`certChainFile`/`privateKeyFile`) — the path form is resolved in `server.ts` only, so the napi `CertConfig` stays inline-only. It writes a `status.json` (`{ pid, version, ports, ... }`) for supervisors, and handles `SIGHUP` (reload) / `SIGTERM`/`SIGINT` (graceful stop). host-manager uses this to supervise symphony out-of-process.

The server also **watches the cert/key files referenced by the config** (grouped by parent dir, deduped, re-derived on every reconcile so watchers don't leak) → a debounced `reconcile()` on change, so an on-disk cert renewal is picked up live without a `config.json` write or restart. Two details make a listener-level cert rotation actually apply: the per-proxy `listenerSig` is computed over the *resolved* listeners (cert contents included), so a rotated `defaultCert`/mTLS file changes the signature and forces a recreate rather than a route-only hot-swap against the frozen `default_listener_tls`. Basename-filtered dir watching handles in-place / rename rotation (what host-manager does); k8s projected-volume `..data` symlink swaps are not yet covered. Cert-failure resilience lives in `router.rs::build_route_table`: a route whose cert can't be built (e.g. rustls `KeyMismatch` from a rotated key vs a stale inlined chain) is isolated — one bad tenant cert never aborts the whole table; on a hot-swap the last-good route is carried forward for that SNI (mid-rotation the old cert is still valid), and on initial build the SNI is simply dropped.

### Data flow

```
TCP accept (SO_REUSEPORT per worker thread)
  └─ sni.rs       peek() — 1 syscall, 512-byte stack buf → PeekInfo { sni, ja3, ja4 }
  └─ protection.rs check() → Block (emit 'blocked', drop) | Allow
  └─ router.rs    RouteTable.resolve(sni) → Route
  └─ [suspended.rs  register, emit 'suspended', await oneshot]
  └─ tls.rs       TlsAcceptor::accept() with handshake timeout (if terminate_tls)
  └─ upstream.rs  connect(Destination, peer_ip) → UpstreamStream
  └─ tokio::io::copy_bidirectional wrapped in idle_timeout
  └─ RAII drop: BalancerGuard, ActiveGuard — all counter decrements happen here
```

### Module map

| File | Responsibility |
|---|---|
| `src/lib.rs` | Crate root; `mod` declarations; `#[macro_use] napi_derive` |
| `src/proxy.rs` | All `#[napi]`-exposed types and methods; config parsing helpers |
| `src/listener.rs` | TCP accept loop for TLS listeners; SO_REUSEPORT per worker; RLIMIT_NOFILE |
| `src/http_listener.rs` | Plaintext HTTP/1.1 accept loop (`mode: 'http'`): ACME-proxy or 301 redirect |
| `src/http_proxy.rs` | HTTP/1.1 header framing and rewrite helpers shared by the HTTP listener |
| `src/sni.rs` | MSG_PEEK ClientHello parser; SNI extraction; JA3 fingerprint |
| `src/router.rs` | RouteTable (exact + wildcard HashMap); ArcSwap hot-swap |
| `src/upstream.rs` | UpstreamStream enum (Tcp/Uds); connect(); TCP_NODELAY; PROXY v1/v2 header encoders; HTTP header injection (XFF, X-JA3/X-JA4) |
| `src/balancer.rs` | UdsBalancer: AtomicU32 least-connections; IP affinity DashMap |
| `src/tls.rs` | rustls ServerConfig builder; SHA-256 deduplication cache |
| `src/mtls.rs` | SymphonyClientVerifier wrapping WebPkiClientVerifier |
| `src/proxy_conn.rs` | Per-connection handler: the full 7-step flow |
| `src/protection.rs` | IP rate limiting, concurrency, CIDR lists, JA3 blocking |
| `src/suspended.rs` | Pending-connection registry (DashMap + oneshot channels) |
| `src/metrics.rs` | AtomicU64 counters: active, accepted, errors, blocked |
| `src/error.rs` | SymphonyError enum → napi::Error conversion |

---

## Key design decisions

### MSG_PEEK for SNI/JA3
A single `stream.peek(&mut buf[..512])` reads the ClientHello without consuming any bytes. Cost: 1 syscall, 512-byte stack buffer, zero heap allocation. This gives us both the SNI (for routing) and the JA3 fingerprint (for protection) before the TLS handshake begins. The alternative — a custom TLS acceptor that extracts SNI internally — would require modifying rustls internals.

### Source-address & fingerprint forwarding (`upstream.rs` + `proxy_conn.rs`)
Per route, `sourceAddressHeader` picks how the client IP reaches the upstream: PROXY v1 (text),
PROXY **v2** (binary, TLV-capable), `X-Forwarded-For` injection, or none. `forwardFingerprint`
(`ja3`/`ja4`/`none`) additionally forwards the ClientHello fingerprint symphony already computes
in `sni.rs`, so backends can make their own bot/abuse decisions on it. Carrier follows the mode:
a PROXY v2 TLV (custom types `0xE0`=JA3 / `0xE1`=JA4, in HAProxy's `0xE0–0xEF` private range) under
`proxyProtocolV2` — which works even in passthrough since it prefixes the raw TLS bytes — otherwise
an injected `X-JA3`/`X-JA4` header. Header injection is gated on `l7_http1` (terminated TLS *and* a
non-h2 negotiated ALPN); it's a no-op in passthrough or on an h2 upstream, so text is never spliced
into TLS ciphertext or an h2 frame stream. `inject_request_headers` also strips any client-supplied
copy of an injected header so the value is authoritative (anti-spoof). `proxy_conn.rs` threads the
fingerprint + the connection's `local_addr` (the PROXY v2 destination) into `apply_source_header`.
Keep v2 **opt-in**: HAProxy/nginx speak it, but Harper core's own UDS reader currently parses v1 only,
so the UDS default stays v1.

### ArcSwap for RouteTable
`ArcSwap<RouteTable>` gives us a pointer-swap on writes (single atomic store) and a single `load()` on reads — no lock contention on the hot path. With ≤100 routes, rebuilding the full table on `updateConfig` costs ~microseconds (Arc pointer clones only). A partial-update scheme would be more complex without meaningful benefit.

### DashMap throughout
`DashMap` provides lock-free concurrent access via internal sharding. Used for:
- `protection.rs`: per-IP state (`ip_table: DashMap<IpAddr, Arc<IpState>>`)
- `balancer.rs`: IP affinity map (`DashMap<IpAddr, Arc<AffinityEntry>>`)
- `suspended.rs`: pending connection registry (`DashMap<u64, oneshot::Sender<...>>`)

### Token bucket via AtomicU32 CAS (×1000 fixed-point)
The rate limit uses a fixed-point token count (×1000) in an `AtomicU32` with CAS retry loops. `Relaxed` ordering is correct here because the token bucket is inherently approximate — a small window of double-allowing at refill time is acceptable and expected. No mutex needed on the hot path.

### SO_REUSEPORT per worker
Each tokio worker thread gets its own listening socket on the same address via `SO_REUSEPORT`. The kernel distributes incoming connections across them using a hash of the 4-tuple. This eliminates the accept lock contention that would occur with a single accepting socket + channel dispatch, and scales linearly with CPU count.

### Suspended connections via oneshot channels
Each suspended connection gets a `tokio::sync::oneshot::channel`. The sender is stored in a `DashMap<u64, Sender>`. `resolveConnection()` removes the sender and fires it — synchronous from the JS side (no async needed). `oneshot` is used rather than `mpsc` because exactly one resolution is possible per connection. If no resolution arrives within `suspendTimeoutMs`, the `timeout(rx.await)` in `proxy_conn.rs` returns an error and the TCP stream is dropped.

### Per-route Arc<ServerConfig> deduplication (TlsConfigCache)
Routes that share the same cert+mTLS combination share a single `Arc<ServerConfig>` allocation. The cache key is `(sha256(cert_pem + key_pem), sha256(mtls_ca_pem))`. Built at config-parse time in `tls.rs::TlsConfigCache`. Important for deployments where many routes share a wildcard cert.

### Send + Sync in napi classes
napi `Buffer` contains raw pointers (`*mut napi_env__`, `*mut napi_ref__`) that are not `Sync`. The `SymphonyProxyWrap` struct must be `Send + Sync`. Solution: napi types (`Buffer`, `JsCertConfig`, etc.) are only used as constructor/method *parameters*, immediately converted to plain Rust (`Vec<u8>`, `ListenerTlsSpec`, etc.), and never stored in the struct. The struct only holds types that are provably `Send + Sync`.

---

## Conventions

- All `#[napi]`-annotated items live in `src/proxy.rs`. Other modules are pure Rust with no napi imports.
- Background tasks (affinity eviction, IP state eviction) are spawned in `start()` and cancelled via the `shutdown_tx` broadcast channel.
- All counter decrements use RAII guards (`BalancerGuard`, `ActiveGuard`). Never decrement in a finally-style chain.
- `Relaxed` ordering for per-connection counters (active, accepted, errors). `AcqRel` only where cross-thread ordering is required — each such site has a comment explaining why.
- Error type: `SymphonyError` → `napi::Error` via `From`. No `unwrap()` on paths reachable from JS.
- `#![deny(clippy::all)]` is set in `lib.rs`. Fix clippy warnings before committing.

---

## How to extend

### Adding a new protection check

1. Add a variant to `protection::BlockReason`
2. Add the check in `ProtectionState::check()` in the correct position (allowlist first, then blocklist, then JA3, then requireSni, then rate limit, then concurrency — cheapest/most-common rejections first)
3. Add a field to `ProtectionConfig` in `protection.rs`
4. Add the field to `JsProtectionConfig` in `proxy.rs` and to `ProtectionConfig` in `ts/types.ts`
5. Wire the field in `parse_protection_config()` in `proxy.rs`
6. Add a test in `__test__/protection.spec.ts`

### Adding a new upstream type

1. Add a variant to `upstream::UpstreamStream` and `router::Destination`
2. Implement `connect()` for the new variant in `upstream.rs`
3. Add a new `*Upstream` interface to `ts/types.ts` and add it to the `Upstream` union
4. Add a new `kind` case in `parse_upstream_spec()` in `proxy.rs`
5. Add a test

### Adding a new napi method

1. Implement in `proxy.rs` with `#[napi]`
2. Add the corresponding method to `SymphonyProxy` in `ts/proxy.ts`
3. Add types to `ts/types.ts` if needed
4. Run `npm run build:debug` to regenerate `ts/addon.d.ts`

---

## Testing

Tests live in `__test__/` and use Node's built-in `node:test` runner.

- **`util.ts`** — self-signed cert generation via `openssl` (or a fallback baked-in cert if openssl is unavailable), free-port helper, echo servers, TLS/TCP round-trip helpers
- **`proxy.spec.ts`** — TLS termination, wildcard SNI routing, `updateConfig` hot-swap
- **`protection.spec.ts`** — rate limit token bucket exhaustion, CIDR blocklist in `blockedIps()`
- **`suspended.spec.ts`** — hold → resolve → proxy, hold → null → close, hold → timeout → drop

Build and run:
```bash
npm run build:debug
npm test
```

Tests bind on random high ports (`port: 0`) to avoid conflicts. Suspended-route tests use short `suspendTimeoutMs` (200ms) to keep the suite fast.

---

## Non-obvious gotchas

- **`copy_bidirectional` half-close**: it returns when *either* side closes, including on RST. The `ActiveGuard` drop handles both clean close and error paths.
- **Affinity bounds check**: after `updateConfig` shrinks the socket list, a stale affinity `socket_idx` may be out of bounds. `balancer.rs::pick()` always bounds-checks before using the affinity index and falls back to least-connections if out of range.
- **`resolveConnection` with unknown ID**: a no-op, not an error. The connection has already timed out and been dropped by the time JS calls this with a stale ID.
- **`ring` vs `md-5`**: `ring 0.17` removed MD5 support. JA3 fingerprints use `md-5 0.10` (RustCrypto). SHA-256 for cert deduplication still uses `ring::digest::SHA256` (ring is a direct dep for this).
- **musl RLIMIT_NOFILE**: musl hard limit is often 1048576. symphony logs a warning at startup if the requested limit exceeds the hard limit and uses the hard limit instead.
- **napi async methods must not take `&mut self`**: use `Mutex<>` for fields that need mutation after construction (currently `shutdown_tx: Mutex<Option<broadcast::Sender<()>>>`).
- **`JsUpstream` is a flat struct**: the TypeScript `Upstream` discriminated union is mapped to a single flat `JsUpstream { kind, host?, port?, path?, ipAffinity?, ipAffinityTtlMs? }` struct on the Rust side to avoid napi union complexity. Fields not relevant to a given `kind` will be `None`.
