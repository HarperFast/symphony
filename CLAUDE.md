# CLAUDE.md — AI/contributor context for symphony

This file is the primary entry point for any AI assistant working on this codebase.

---

## Architecture

symphony is a **napi-rs cdylib** loaded by Node.js. The tokio multi-thread runtime is embedded via napi's `tokio_rt` feature. The JS API is a thin `EventEmitter` wrapper (`ts/proxy.ts: SymphonyProxy`) over the napi class (`src/proxy.rs: SymphonyProxyWrap`).

### Standalone server (`ts/server.ts` → `dist/server.js`, the `symphony-server` bin)

For consumers that want symphony as its own OS process rather than embedded in their Node app, the package ships a `symphony-server` bin. It reads a JSON config file (`{ version, proxies: [{ listeners, routes }] }` — one entry per port-set, since the route table is per-proxy), constructs a `SymphonyProxy` per entry, and **watches the config file** to hot-reload (route change → `updateConfig`; listener change → recreate that proxy). Cert material may be given inline (`certChain`/`privateKey`) or by path (`certChainFile`/`privateKeyFile`) — the path form is resolved in `server.ts` only, so the napi `CertConfig` stays inline-only. It writes a `status.json` (`{ pid, version, ports, ... }`) for supervisors, and handles `SIGHUP` (reload) / `SIGTERM`/`SIGINT` (graceful stop). host-manager uses this to supervise symphony out-of-process.

### Admin/metrics endpoint (`ts/admin.ts`)

An optional `admin` block in the config file (`{ socketPath?, socketMode?, port?, host? }`) makes `symphony-server` expose `GET /metrics` (Prometheus text), `/metrics.json`, and `/health` over a Unix socket, a loopback TCP port, or both. It exists because an out-of-process symphony has no reachable napi `metrics()` — the endpoint is the only export path for that deployment.

Three properties are load-bearing and easy to regress:

- **It must never affect proxying.** A bind failure is logged and retried on a 5s timer instead of throwing out of `doReconcile()`. This is not defensiveness for its own sake: during a version upgrade host-manager runs both processes concurrently (the Rust listeners overlap via `SO_REUSEPORT`, which a Node HTTP server has no equivalent for), so the successor *will* lose the admin bind for a few seconds and must keep serving traffic anyway.
- **A stale Unix socket is reclaimed, a live one is not.** Three things protect this, and each was a real hole once: the probe counts a path reclaimable only on `ECONNREFUSED` (an `EACCES` from a restrictively-permissioned live socket is not evidence nobody is listening); the inode must actually be a socket (a `socketPath` misconfigured onto a regular file would otherwise be deleted); and the bind happens on a pid-unique temp path that is `rename`d into place, so there is no probe→unlink→bind window for a second process to delete a socket the first has already bound. On shutdown the published path is unlinked only while its inode is still the one we put there. Same family as the `status.json` ownership guard.
- **Counters are read per request**, not cached at reconcile, so a scrape never serves numbers frozen at the last config reload.
- **Totals are derived, never maintained alongside their parts.** `blocked`/`errors` are summed from the per-reason values in the same snapshot, and the proxy-wide blocked total from the listener values. A separate `total_blocked` incremented next to its reason counter is two non-atomic writes: a scrape landing between them sees a total that disagrees with its own breakdown, so the invariant would hold only while the proxy is idle — precisely when nobody is reading it.
- **Route label cardinality is configuration-bounded.** A resolved `Route` owns its configured SNI/wildcard identity and optional metrics group; metric call sites never accept the client SNI/Host as a label. Route errors omit zero-valued reasons so scrape size does not multiply every reason by every tenant.

Prometheus shape: blocked/error counts are emitted **only** under their `reason` label (they sum to the unlabeled total, so a separate total would be a second representation of the same number), and the proxy-wide active gauge is `sum without(listener)`. `renderPrometheus` is exported from the package for embedded consumers.

The server also **watches the cert/key files referenced by the config** (grouped by parent dir, deduped, re-derived on every reconcile so watchers don't leak) → a debounced `reconcile()` on change, so an on-disk cert renewal is picked up live without a `config.json` write or restart. Two details make a listener-level cert rotation actually apply: the per-proxy `listenerSig` is computed over the *resolved* listeners (cert contents included), so a rotated `defaultCert`/mTLS file changes the signature and forces a recreate rather than a route-only hot-swap against the frozen `default_listener_tls`. Basename-filtered dir watching handles in-place / rename rotation (what host-manager does); k8s projected-volume `..data` symlink swaps are not yet covered. Cert-failure resilience lives in `router.rs::build_route_table`: a route whose cert can't be built (e.g. rustls `KeyMismatch` from a rotated key vs a stale inlined chain) is isolated — one bad tenant cert never aborts the whole table; on a hot-swap the last-good route is carried forward for that SNI (mid-rotation the old cert is still valid), and on initial build the SNI is simply dropped.

### Data flow

```
TCP accept (SO_REUSEPORT per worker thread)
  └─ sni.rs       peek() — MSG_PEEK ClientHello (reassembled when fragmented) → PeekInfo { sni, ja3, ja4, complete }
  └─ protection.rs check() → Block (emit 'blocked', drop) | Allow
  └─ router.rs    RouteTable.resolve(sni) → Route
  └─ [suspended.rs  register, emit 'suspended', await oneshot]
  └─ tls.rs       TlsAcceptor::accept() with handshake timeout (if terminate_tls)
  └─ upstream.rs  connect(Destination, peer_ip) → UpstreamStream
  └─ tokio::io::copy_bidirectional_with_sizes wrapped in idle_timeout
       (per-direction buffers from readBufferSize / client|upstreamReadBufferSize)
  └─ RAII drop: BalancerGuard, ActiveGuard, RouteActiveGuard — all counter decrements happen here
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
| `src/metrics.rs` | AtomicU64 counters (active, accepted, bytes, per-reason blocks/errors) + `CountingStream` |
| `src/error.rs` | SymphonyError enum → napi::Error conversion |

---

## Key design decisions

### MSG_PEEK for SNI/JA3/JA4
`stream.peek()` reads the ClientHello without consuming any bytes, giving SNI (routing) and the JA3/JA4 fingerprints (protection) before the TLS handshake begins. The alternative — a custom TLS acceptor that extracts SNI internally — would require modifying rustls internals.

Because a single peek returns only whatever bytes are currently buffered, `peek()` **reassembles**: it reads the declared ClientHello length from the record+handshake headers and re-peeks (into a growing buffer, bounded by `MAX_CLIENT_HELLO` and `REASSEMBLY_TIMEOUT`) until the whole hello is present, setting `PeekInfo::complete`. This closes a blocklist-bypass: without it, a client fragments the ClientHello so symphony computes a different/empty fingerprint while rustls later accepts the full handshake. `protection.rs` fails closed on `!complete` when a JA3/JA4 blocklist is configured (`BlockReason::IncompleteHandshake`).

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

### ArcSwap for ProtectionConfig (hot-swappable)
`ProtectionState.config: ArcSwap<ProtectionConfig>` holds *all* protection settings as one swappable snapshot — CIDR allowlist/blocklist, JA3 blocklist, rate limit parameters, concurrency cap, handshake timeout, and requireSni are all inside `ProtectionConfig`. This means one atomic `store()` in `updateConfig` reaches all checks for a listener with zero hot-path cost. `check()` calls `config.load()` once per connection, which is a single lock-free pointer load. Callers identify listeners by port (`JsHotConfig.protection: [{ port, protection }]`).

**Invariant:** protection *presence* (None vs Some) is fixed at listener construction — the `Option<Arc<ProtectionState>>` in `ListenerState` never changes after `start()`. `update_config` returns an error for ports that match no listener or that were started without protection. The `symphony-server` reconcile path enforces this by including `hasProtection` in the per-listener signature: none→some and some→none transitions change the signature and trigger a seamless proxy recreate (SO_REUSEPORT, no bind gap); only contents-only changes reach the hot-swap path.

### DashMap throughout
`DashMap` provides lock-free concurrent access via internal sharding. Used for:
- `protection.rs`: per-IP state (`ip_table: DashMap<IpAddr, Arc<IpState>>`)
- `balancer.rs`: IP affinity map (`DashMap<IpAddr, Arc<AffinityEntry>>`)
- `suspended.rs`: pending connection registry (`DashMap<u64, oneshot::Sender<...>>`)

### Token bucket via AtomicU32 CAS (×1000 fixed-point)
The rate limit uses a fixed-point token count (×1000) in an `AtomicU32` with CAS retry loops. `Relaxed` ordering is correct here because the token bucket is inherently approximate — a small window of double-allowing at refill time is acceptable and expected. No mutex needed on the hot path.

Each IP now has **two independent token buckets** on `IpState`: a per-second bucket (`tokens`, `last_refill_ns`) and a sustained per-minute bucket (`sustained_tokens`, `sustained_last_refill_ns`). Both use the same ×1000 fixed-point and CAS idiom. Both are checked on admission; exhausting either blocks the connection. Max sustained burst: 4,294,967 connections (u32::MAX / 1000) — far above any realistic value.

### Monotonic clock for all timing
`now_ns()` returns a monotonic offset from a process-wide `Instant` anchor (`static START: OnceLock<Instant>`), NOT wall-clock nanoseconds. All penalty deadlines and bucket timestamps use this value. Trade-off: values cannot be interpreted as unix timestamps; they are only ever compared internally. Benefit: forward NTP steps cannot release a penalty-boxed IP early and backward steps cannot freeze bucket refills.

### Penalty box via AtomicU64 deadline
When `penaltyBox.durationMs > 0`, exhausting any rate limit sets `IpState.penalty_deadline_ns = now_ns() + duration_ns`. While `now < deadline`, connections are blocked as `PenaltyBoxed`. Each blocked attempt while boxed also debits the token buckets (lazy refill + consume); if a bucket exhausts, the deadline is reset to `now + duration_ns` (extension). The IP is readmitted once the deadline passes without further extension. Penalty state lives on `IpState` and survives config hot-swaps. A `durationMs` hot-swap affects new stamps only; existing deadlines run out on the old duration.

### IP state eviction (spawned in start())
`ProtectionState::evict()` is spawned as a periodic background task (60 s interval) per listener with protection, in `start()` via the `shutdown_tx` broadcast pattern. Eviction uses **lazy bucket projection** — it computes what the token level *would* be if refilled by the current time (`now - last_refill_ns`), rather than relying on the stored token value (which is only updated on access). An entry is retained if:
- It is in the penalty box (`penalty_deadline_ns > now`).
- It has active connections (`active > 0`).
- Its per-second bucket would not yet be fully refilled (projected tokens < burst_fp).
- Its sustained bucket would not yet be fully refilled (projected sustained_tokens < sustained_burst_fp).

This prevents an attacker from resetting their sustained window by pausing long enough for the eviction interval to pass.

### SO_REUSEPORT per worker
Each tokio worker thread gets its own listening socket on the same address via `SO_REUSEPORT`. The kernel distributes incoming connections across them using a hash of the 4-tuple. This eliminates the accept lock contention that would occur with a single accepting socket + channel dispatch, and scales linearly with CPU count.

### Suspended connections via oneshot channels
Each suspended connection gets a `tokio::sync::oneshot::channel`. The sender is stored in a `DashMap<u64, Sender>`. `resolveConnection()` removes the sender and fires it — synchronous from the JS side (no async needed). `oneshot` is used rather than `mpsc` because exactly one resolution is possible per connection. If no resolution arrives within `suspendTimeoutMs`, the `timeout(rx.await)` in `proxy_conn.rs` returns an error and the TCP stream is dropped.

### Per-route Arc<ServerConfig> deduplication (TlsConfigCache)
Routes that share the same cert+mTLS combination share a single `Arc<ServerConfig>` allocation. The cache key is `(sha256(cert_pem + key_pem), sha256(mtls_ca_pem), http2)`. Important for deployments where many routes share a wildcard cert.

The cache is owned by `SymphonyProxyWrap` and **threaded through every `build_route_table`** rather than created per build. That is what makes TLS session resumption survive a config reload, and it is the non-obvious part: `build_server_config` gives each `ServerConfig` its own `session_storage` (TLS 1.2 session IDs) and its own `Ticketer` (TLS 1.3 ticket keys), so minting a fresh config for an *unchanged* cert silently invalidates every ticket already issued. Nothing errors — clients just quietly fall back to full handshakes. Since a route add/remove or an on-disk cert renewal rebuilds the whole table, a per-build cache meant clients almost never resumed. Keying on the cert bytes gives the right lifetime for free: session state lives exactly as long as the cert it was issued under, and a rotation retires it.

Two properties keep that honest:

- **The sweep is the caller's, at the commit point.** `retain_used()` (mark-and-sweep over the keys touched during a build) runs in `proxy.rs` *after* the new table is swapped in — never inside `build_route_table`. `updateConfig` is all-or-nothing: a route build can succeed and then be discarded when the protection half fails validation, and sweeping against a table that never went live would retire configs the still-running table is serving from. Over-retaining for one generation is the safe direction; under-retaining costs live session state.
- **Ticket keys stay per-config, not process-global.** A process-wide ticketer would let a ticket minted under one tenant's cert resume against another tenant's route. Sharing across configs is the obvious "optimisation" here and it is the wrong one.

Two things are deliberately *not* solved: rustls' ring `Ticketer` rotates keys on its own ~6h schedule (independent of reloads), and ticket keys are per-process, so during host-manager's overlapping-process upgrade window clients that land on the new process fall back to a full handshake until they hold one of its tickets. Both degrade to a full handshake, never to an error. `__test__/session-resumption.spec.ts` covers all of this end-to-end (TLS 1.2 and 1.3, reload, and rotation).

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

### Adding a new metric

1. Add the counter to `ListenerMetrics`/`RouteMetrics`/`GlobalMetrics` in `metrics.rs`, or a variant to the
   `labeled_enum!` block for `BlockKind`/`ErrorKind` — the variant list drives the counter array,
   the label, and the export, so there is no second list to update.
2. Increment it at the call site. A new `protection::BlockReason` variant will fail to compile
   until `From<&BlockReason> for BlockKind` maps it — that is deliberate, so a new protection
   check can't land in an unlabeled bucket.
3. Surface it in `JsProxyMetrics`/`JsListenerMetrics` (`proxy.rs`), `ts/types.ts`, and the
   mapping in `ts/proxy.ts`.
4. Add the sample to `renderPrometheus` in `ts/admin.ts`, and a case in `__test__/metrics.spec.ts`.

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
- **`mtls.spec.ts`** — mTLS termination + PROXY v2 TLV forwarding of the client cert chain (0xE2, SSL TLV 0x20); skips without openssl
- **`metrics.spec.ts`** — per-listener breakdown and byte counting, `renderPrometheus` output shape, the admin endpoint over UDS + TCP, and stale-socket reclaim after a `SIGKILL`

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
