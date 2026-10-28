# CLAUDE.md — AI/contributor context for symphony

This file is the primary entry point for any AI assistant working on this codebase.

---

## Architecture

symphony is a **napi-rs cdylib** loaded by Node.js. The tokio multi-thread runtime is embedded via napi's `tokio_rt` feature. The JS API is a thin `EventEmitter` wrapper (`ts/proxy.ts: SymphonyProxy`) over the napi class (`src/proxy.rs: SymphonyProxyWrap`).

### Standalone server (`ts/server.ts` → `dist/server.js`, the `symphony-server` bin)

For consumers that want symphony as its own OS process rather than embedded in their Node app, the package ships a `symphony-server` bin. It reads a JSON config file (`{ version, proxies: [{ listeners, routes }] }` — one entry per port-set, since the route table is per-proxy), constructs a `SymphonyProxy` per entry, and **watches the config file** to hot-reload (route change → `updateConfig`; listener change → recreate that proxy). Cert material may be given inline (`certChain`/`privateKey`) or by path (`certChainFile`/`privateKeyFile`) — the path form is resolved in `server.ts` only, so the napi `CertConfig` stays inline-only. It writes a `status.json` (`{ pid, version, startedAt, ports, ... }`) for supervisors that names the newest live process on that config. No process deletes it on stop, because a successor can rename its status over the path between an ownership check and the unlink; supervisors read a dead pid as not running. Every process reads it once a second for life (`recheckStatus`, after a faster 1/2/4/8-poll phase following each own write): a newer same-config owner makes it stop rewriting the file, and a dead or older owner makes it take the file back, which also covers incumbents that predate the guard. It handles `SIGHUP` (reload) / `SIGTERM`/`SIGINT` (graceful stop). host-manager uses this to supervise symphony out-of-process.

**An outgoing process stops itself (symphony#53).** host-manager spawns symphony detached so proxying survives host-manager restarts, so nothing kills an incumbent whose handoff failed partway, and `SO_REUSEPORT` lets both processes accept forever. `considerStandingDown` (in the yield branch of `writeStatus`) runs the normal `SIGTERM` stop once one newer owner, identified by `(pid, startedAt)`, has held `status.json` continuously for `SUPERSEDE_GRACE_MS` (10 s). Four conditions keep that from ever leaving nothing serving, and each closes a real hole:

- **`start()` resolving means bound.** `SymphonyProxyWrap::start` binds every worker socket of every listener (`listener::bind_workers`) before it spawns any accept loop, and rejects with nothing listening if one fails. Before, it returned before binding, so a successor whose bind failed still published `status.json` and could retire the only working process.
- **Coverage.** The owner's `listeners` (`host:port` of its committed proxies) must include every listener this process has. A successor that could not read a listener cert this process still has cached would otherwise take over without that port.
- **Verified identity.** `servesConfig` must read `/proc/<pid>/cmdline` and `cwd` (the peer's `--config` is resolved against its own cwd, so relative paths match) and the status `configPath` must match. The liveness-only fallback without `/proc` still yields the file but never retires.
- **Continuous tenure.** The clock restarts when the owner changes, dies, stops qualifying, or the file names this process again. 10 s exceeds host-manager's reap of a failed successor (its 10 s readiness wait, then SIGTERM and SIGKILL after 5 s), so a successor being reaped is seen to exit first.

The last check is the tick that calls `onSuperseded`. A successor that dies during the stop itself (admin close, pending reconcile, 100 ms per proxy) is not re-checked, and the supervisor's health poll respawns. `PR_SET_PDEATHSIG` is deliberately not used: dying with host-manager would cut all traffic on every host-manager restart.

### Admin/metrics endpoint (`ts/admin.ts`)

An optional `admin` block in the config file (`{ socketPath?, socketMode?, port?, host? }`) makes `symphony-server` expose `GET /metrics` (Prometheus text), `/metrics.json`, and `/health` over a Unix socket, a loopback TCP port, or both. It exists because an out-of-process symphony has no reachable napi `metrics()` — the endpoint is the only export path for that deployment.

Three properties are load-bearing and easy to regress:

- **It must never affect proxying.** A bind failure is logged and retried on a 5s timer instead of throwing out of `doReconcile()`. This is not defensiveness for its own sake: during a version upgrade host-manager runs both processes concurrently (the Rust listeners overlap via `SO_REUSEPORT`, which a Node HTTP server has no equivalent for), so the successor *will* lose the admin bind for a few seconds and must keep serving traffic anyway.
- **A stale Unix socket is reclaimed, a live one is not.** Three things protect this, and each was a real hole once: the probe counts a path reclaimable only on `ECONNREFUSED` (an `EACCES` from a restrictively-permissioned live socket is not evidence nobody is listening); the inode must actually be a socket (a `socketPath` misconfigured onto a regular file would otherwise be deleted); and the bind happens on a pid-unique temp path that is `rename`d into place, so there is no probe→unlink→bind window for a second process to delete a socket the first has already bound. On shutdown the published path is unlinked only while its inode is still the one we put there. Same family as the `status.json` ownership guard.
- **Counters are read per request**, not cached at reconcile, so a scrape never serves numbers frozen at the last config reload.
- **Totals are derived, never maintained alongside their parts.** `blocked`/`errors` are summed from the per-reason values in the same snapshot, and the proxy-wide blocked total from the listener values. A separate `total_blocked` incremented next to its reason counter is two non-atomic writes: a scrape landing between them sees a total that disagrees with its own breakdown, so the invariant would hold only while the proxy is idle — precisely when nobody is reading it.
- **Route label cardinality is configuration-bounded.** A resolved `Route` owns its configured SNI/wildcard identity and optional metrics group; metric call sites never accept the client SNI/Host as a label. Route errors omit zero-valued reasons so scrape size does not multiply every reason by every tenant.

Prometheus shape: blocked/error counts are emitted **only** under their `reason` label (they sum to the unlabeled total, so a separate total would be a second representation of the same number), and the proxy-wide active gauge is `sum without(listener)`. `renderPrometheus` is exported from the package for embedded consumers.

The server also **watches the cert/key files referenced by the config** (grouped by parent dir, deduped, re-derived on every reconcile so watchers don't leak) → a debounced `reconcile()` on change, so an on-disk cert renewal is picked up live without a `config.json` write or restart. Two details make a listener-level cert rotation actually apply: the per-proxy `listenerSig` is computed over the *resolved* listeners (cert contents included), so a rotated `defaultCert`/mTLS file changes the signature and forces a recreate rather than a route-only hot-swap against the frozen `default_listener_tls`. Basename-filtered dir watching handles in-place / rename rotation (what host-manager does); k8s projected-volume `..data` symlink swaps are not yet covered. Cert-failure resilience lives in `router.rs::build_route_table`: a route whose cert can't be built (e.g. rustls `KeyMismatch` from a rotated key vs a stale inlined chain) is isolated — one bad tenant cert never aborts the whole table; on a hot-swap the last-good route is carried forward for that SNI (mid-rotation the old cert is still valid), and on initial build the SNI is simply dropped. Carry-forward is conditional on the client-certificate policy: the last-good `ServerConfig` *is* its client verifier, so it is kept only while the new spec asks for the same `ClientAuth` (passthrough / no client cert / SHA-256 of the effective CA bundle + `requireClientCert`) — otherwise the SNI is tombstoned, or a route newly requiring mTLS would keep admitting certless clients until a later reload built (symphony#62). The policy lives in `RouteTable.client_auth`, not on `Route`, because every connection clones `Route` into its task. For the comparison to see the requested policy, `server.ts::resolveRoute` keeps the resolved `mtls` on a cert-file read failure, and substitutes an empty CA bundle (which can never build, so never matches) when the CA file itself is unreadable; a passthrough route ignores `mtls`, so this only drops terminating routes. One spec decides each configured SNI even when it is rejected (the last exact duplicate, the first wildcard), so a duplicate can't serve a tombstoned SNI under another policy.

### Data flow

```
TCP accept (SO_REUSEPORT per worker thread)
  └─ [ingress.rs  failoverIngress only: trustedSources gate, read PROXY v2 → peer addr]
  └─ sni.rs       peek() — MSG_PEEK ClientHello (reassembled when fragmented) → PeekInfo { sni, ja3, ja4, complete }
  └─ protection.rs check() → Block (emit 'blocked', drop) | Allow
  └─ router.rs    RouteTable.resolve(sni) → Route
  └─ route.allowed_sources.permits(peer) → 'source_not_allowed' block | continue
  └─ [failover.rs route down or draining → forward_to_peers (raw TLS) | ingress: close]
  └─ [suspended.rs  register, emit 'suspended', await oneshot]
  └─ tls.rs       TlsAcceptor::accept() with handshake timeout (if terminate_tls)
  └─ upstream.rs  connect(Destination, peer_ip) → UpstreamStream
  └─ tokio::io::copy_bidirectional_with_sizes wrapped in idle_timeout
       (per-direction buffers from readBufferSize / client|upstreamReadBufferSize)
       (both halves wrapped in liveness::Watched, raced against the half-close bound)
  └─ RAII drop: BalancerGuard, ActiveGuard, RouteActiveGuard — all counter decrements happen here
```

### Module map

| File | Responsibility |
|---|---|
| `src/lib.rs` | Crate root; `mod` declarations; `#[macro_use] napi_derive`; jemalloc as the global allocator on Linux |
| `src/proxy.rs` | All `#[napi]`-exposed types and methods; config parsing helpers |
| `src/listener.rs` | TCP accept loop for TLS listeners; SO_REUSEPORT per worker; RLIMIT_NOFILE |
| `src/liveness.rs` | Dead-peer detection: TCP keepalive on the listening socket; the half-close bound |
| `src/http_listener.rs` | Plaintext HTTP/1.1 accept loop (`mode: 'http'`): ACME-proxy or 301 redirect |
| `src/http_proxy.rs` | HTTP/1.1 header framing and rewrite helpers shared by the HTTP listener |
| `src/sni.rs` | MSG_PEEK ClientHello parser; SNI extraction; JA3 fingerprint |
| `src/router.rs` | RouteTable (exact + wildcard HashMap); ArcSwap hot-swap |
| `src/upstream.rs` | UpstreamStream enum (Tcp/Uds); connect(); TCP_NODELAY; PROXY v1/v2 header encoders; HTTP header injection (XFF, X-JA3/X-JA4) |
| `src/balancer.rs` | UdsBalancer: AtomicU32 least-connections; IP affinity DashMap; per-slot `SlotHealth` (failover routes only) |
| `src/failover.rs` | Peer failover: policy parsing, per-(route, peer) cooldown, `forward_to_peers`, the recovery probe + `routeHealth` |
| `src/ingress.rs` | Failover ingress listener: `trustedSources` gate and the PROXY v2 reader |
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
(`ja3`/`ja4`/`none`, or `['ja3','ja4']` for both) additionally forwards the ClientHello fingerprints
symphony already computes in `sni.rs`, so backends can make their own bot/abuse decisions on them.
It parses to a set (`router::ForwardFingerprint`), and every member rides the route's one carrier,
so the carrier checks (`requires_http_protocol`, "no carrier") depend only on the set being
non-empty. Carrier follows the mode: a PROXY v2 TLV (custom types `0xE0`=JA3 / `0xE1`=JA4, in HAProxy's `0xE0–0xEF` private range) under
`proxyProtocolV2` — which works even in passthrough since it prefixes the raw TLS bytes — otherwise
an injected `X-JA3`/`X-JA4` header. Header injection is gated on `l7_http1` (terminated TLS *and* a
non-h2 negotiated ALPN); it's a no-op in passthrough or on an h2 upstream, so text is never spliced
into TLS ciphertext or an h2 frame stream. `inject_request_headers` also strips any client-supplied
copy of an injected header so the value is authoritative (anti-spoof). `proxy_conn.rs` threads the
fingerprint + the connection's `local_addr` (the PROXY v2 destination) into `apply_source_header`.
Keep v2 **opt-in**: HAProxy/nginx speak it, but Harper core's own UDS reader currently parses v1 only,
so the UDS default stays v1.

### IPv4 clients of a dual-stack listener are IPv4 everywhere
A `[::]` listener reports an IPv4 client as `::ffff:a.b.c.d`, and `IpNetwork::contains` is
family-strict. Every place that matches a peer against CIDRs converts it with `to_canonical()`:
`ProtectionState::check_at` (once, at the top, so the `ip_table` key for rate/penalty/concurrency
state is canonical too — one client, one bucket; symphony#68), `SourceAllowlist::permits`
(`allowedSources`, ingress `trustedSources`). Every CIDR list is parsed by
`router::parse_source_network`, which stores a mapped entry as IPv4; a mapped entry left in v6 form
would never match a canonical peer. The address forwarded upstream and reported in `'blocked'`
events is left as accepted.

### The default route (`sni: ''`)
`build_route_table` puts the empty-SNI spec in `RouteTable::default` (symphony#47); everything
before insertion — duplicate selection, tombstones, cert carry-forward, `client_auth` — keys it by
`""` like any other SNI, and `get_for_spec_sni("")` returns `default` so carry-forward finds it.
`resolve_with(sni, allow_default: false)` is used where only a route configured for the name may
answer: the failover ingress, and the ACME http-01 proxy in `http_listener.rs` (a default upstream
answering challenges for any `Host` could validate certificates for names it does not serve).
`RouteTable::resolve` is test-only so production lookups state that choice.

### Per-route `allowedSources` (`router.rs::SourceAllowlist`)
A route attribute, not a protection check: protection runs before route selection and is
per-listener, while tenants share listeners and are told apart only by SNI. Four placements are
load-bearing:

- **Checked before the route rate limiter and before suspension** (`proxy_conn.rs`, and the ACME
  path in `http_listener.rs`). After the limiter, refused peers would drain the route-wide bucket
  and deny listed clients; after suspension, JS would see them. A `resolveConnection()` route's
  own list is checked again after resolution (both apply).
- **Assigned after the carry-forward branch in `build_route_table`**, not inside `build_route`.
  The list is independent of the `ServerConfig`, so a carried-forward last-good route takes the
  *new* spec's list; otherwise narrowing a list during a cert-rotation race would keep admitting
  the removed peers until the cert healed.
- **An invalid entry tombstones the route** (fail-closed, never carried forward) instead of
  failing `updateConfig`. A throw from `parse_route_spec` would block reloads (cert renewals
  included) for every tenant on the port-set over one tenant's typo.
- **Canonicalisation (`to_canonical`) happens only inside `permits`**, so the peer address that
  listener protection and the PROXY/XFF encoders see is unchanged. IPv4-mapped CIDRs are stored
  as IPv4 at parse time for the same reason.

### Peer failover (`failover.rs`, `ingress.rs`)
symphony#70. A route with `failover` forwards new connections, as raw TLS and before the handshake,
to a peer's `failoverIngress` listener while its local upstream is down or `drain` is set. Raw TLS
because the decision has to precede the handshake (the local connect happens after it, too late to
hand over the TLS session), and it lets the peer terminate and verify client certs itself.

- **Nothing past the ClientHello reaches a peer that may be retried.** `forward_to_peers` reads
  exactly `PeekInfo::hello_len` wire bytes (through the end of the record that completes the hello,
  never the reassembled buffer), sends PROXY v2 + hello, and `peek`s for the peer's first byte
  before reading the client again. Once a peer byte has arrived the attempt is committed: no retry
  after that, and the byte reaches the client through the ordinary copy.
  An incomplete peek is never forwarded. rustls early data is not enabled anywhere; keep it so.
- **Health is opt-in.** Only a failover route's balancer gets `SlotHealth` (`with_health`), because
  only the probe clears it; an untracked balancer that skipped a refusing slot would never re-test it.
  Every UDS set does get next-slot retry on a refused connect (no state, failure path only). A TCP
  destination's one-slot health lives on `Failover::tcp_health`, so `Destination::Tcp` stays a value.
- **Health is shared across reloads, not copied.** A rebuild reuses the previous `Arc<SlotHealth>`
  per unchanged path/addr, so a connection on the old table marks what the live table reads. The
  probe and a successful connect both clear with `clear_if_unchanged(observed)` (the value read
  before connecting), so neither can erase a newer refusal, and an accepting slot costs no write.
  Peer state and counters carry only when the route keeps its metric identity.
- **Slots tracked ⇔ route has failover**, enforced in `build_route_table` even for a carried-forward
  route (its destinations are rebuilt when the policy's presence changed). A tracked slot with no
  probe would be skipped forever; a failover route without tracking would never go down.
- **Policy is applied after the cert carry-forward branch**, like `allowed_sources`, so a reload that
  sets `drain` during a cert rotation still drains. An invalid policy serves the route without
  failover (availability must not cost the tenant its route); `allowedSources` tombstones because it
  is a restriction.
- **Down = h1 OR h2 destination all refusing**: the client picks its protocol in the handshake we are
  deciding before.
- **Ingress never forwards and never uses a default route** (`resolve_with(sni, false)`); a down or
  draining failover route closes before the handshake. That zero-byte close is the forwarder's
  "next peer" signal, which is how loops are ruled out without a hop counter. The trust gate reads
  no byte; empty `trustedSources` admits nobody; only the header's source address is used (TLVs
  ignored). Ingress *presence* is fixed at construction like protection; `trustedSources` hot-swaps
  through `ArcSwap`, validated with the rest of `updateConfig` before anything is stored.
- **The probe task is the only writer of `reported_down`**, so each transition emits one
  `routeHealth`. It dedups endpoints across routes, runs probes concurrently, and stops on shutdown.

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

The cache is owned by `SymphonyProxyWrap` and **threaded through every `build_route_table`** (and every `resolveConnection`) rather than created per build. That is what makes TLS session resumption survive a config reload, and it is the non-obvious part: `build_server_config` gives each `ServerConfig` its own `session_storage` (TLS 1.2 session IDs) and its own `Ticketer` (TLS 1.3 ticket keys), so minting a fresh config for an *unchanged* cert silently invalidates every ticket already issued. Nothing errors — clients just quietly fall back to full handshakes. Since a route add/remove or an on-disk cert renewal rebuilds the whole table, a per-build cache meant clients almost never resumed. Keying on the cert bytes gives the right lifetime for free: session state lives exactly as long as the cert it was issued under, and a rotation retires it.

Four properties keep that honest:

- **What survives a sweep is decided by the refcount, not the mark set.** `retain_used()` keeps an entry when it was marked during the build *or* when `Arc::strong_count > 1`, and the second clause is the load-bearing one: the carry-forward branch in `build_route_table` (mid-rotation cert/key mismatch) reuses the previous table's `Arc` without going through `get_or_build`, so a live route can be unmarked. Since the table is swapped in before the sweep runs, a committed table's configs always have `strong_count >= 2`. `clear_used()` at the top of a build evicts on the same rule inverted (`strong_count == 1` — cache-only), which is what bounds a reload that fails validation over and over.
- **The sweep is the caller's, at the commit point.** `retain_used()` (mark-and-sweep over the keys touched during a build) runs in `proxy.rs` *after* the new table is swapped in — never inside `build_route_table`. `updateConfig` is all-or-nothing: a route build can succeed and then be discarded when the protection half fails validation, and a sweep driven by that build's marks names none of the live table's configs. The refcount clause above spares them regardless, so this is the belt to that suspenders — but it is what keeps the placement from depending on it. Over-retaining for one generation is the safe direction; under-retaining costs live session state.
- **Configs nothing references are bounded without a reload.** `suspended.rs::build_resolved_route` draws from the same cache, but no table holds a resolved config, so it lives by refcount alone: kept while a connection holds it, otherwise dropped by the next build's `clear_used()` (even one `updateConfig` then rejects) or when an insert pushes the cache past `evict_at`. That threshold is `max(256, 2 × the configs still referenced after the last eviction)`. Without it, a proxy that never reloads keeps a config — with a session store preallocated for 1024 entries — for every distinct cert JS has ever resolved; the doubling keeps the scan amortised O(1) when the route table alone holds more than 256. A resolution carrying the same material as a table route *is* that route's entry, which is safe because the cache key covers every input to what a resumed session may skip (cert, key, client-auth CA and requirement, ALPN).
- **Ticket keys stay per-config, not process-global.** A process-wide ticketer would let a ticket minted under one tenant's cert resume against another tenant's route. Sharing across configs is the obvious "optimisation" here and it is the wrong one.

Scope: the cache belongs to one proxy and lives as long as that `SymphonyProxy` does. A reload that only changes routes keeps it; anything that changes a listener signature — including an on-disk rotation of a listener `defaultCert`/mTLS CA, since `server.ts` computes `listenerSig` over the *resolved* listeners — recreates the proxy, and every route on that port starts over with fresh ticketers. Hoisting the cache to process scope would fix that (it is keyed on cert bytes, so it cannot leak a ticket across tenants) and is not done here.

Two further things are deliberately *not* solved: rustls' ring `Ticketer` rotates keys on its own ~6h schedule (independent of reloads), and ticket keys are per-process, so during host-manager's overlapping-process upgrade window clients that land on the new process fall back to a full handshake until they hold one of its tickets. Both degrade to a full handshake, never to an error. `__test__/session-resumption.spec.ts` covers all of this end-to-end (TLS 1.2 and 1.3, reload, rotation, and suspended-route resolutions).

### Send + Sync in napi classes
napi `Buffer` contains raw pointers (`*mut napi_env__`, `*mut napi_ref__`) that are not `Sync`. The `SymphonyProxyWrap` struct must be `Send + Sync`. Solution: napi types (`Buffer`, `JsCertConfig`, etc.) are only used as constructor/method *parameters*, immediately converted to plain Rust (`Vec<u8>`, `ListenerTlsSpec`, etc.), and never stored in the struct. The struct only holds types that are provably `Send + Sync`.

### jemalloc as the Rust allocator on Linux (`src/lib.rs`, default `jemalloc` feature)
glibc keeps a fan-out node's peak footprint after its connections close: freed chunks are scattered across per-thread arenas, and glibc returns only the top of a heap. On a 100k ↔ 10k churned soak glibc held ~100% of peak at every trough and at zero connections, and its peaks crept up cycle over cycle; jemalloc fell to ~28% of peak at each trough and stayed flat. `--cargo-flags=--no-default-features` builds on the system allocator, for bisecting.

- **Prefixed symbols are what make it safe in a Node process.** tikv-jemallocator exports `_rjem_*`, so only Rust's `#[global_allocator]` reaches it and Node/V8 stay on glibc. The invariant that follows: memory is freed by the allocator that allocated it. It holds because nothing crosses the boundary by ownership — JS `Buffer` arguments are borrowed (napi-rs unrefs them on drop, never frees the bytes) and `pem_bytes` copies them; values returned to JS are copied by `napi_create_*`; the class wrapper and threadsafe-function payloads are freed by Rust code in napi-rs's finalizers. Returning a Rust `Vec` to JS as an external buffer would still be fine (its finalizer is Rust), but a C library that `free()`s memory Rust allocated, or vice versa, would crash.
- **`disable_initial_exec_tls`** is required: Node `dlopen()`s the addon, and jemalloc's default TLS model cannot be dlopened.
- **arm64 page size is fixed at build time** (`.cargo/config.toml`): jemalloc refuses to start on a kernel whose pages are larger than the ones it was built for, and a cross build would detect the builder's 4 KiB. The aarch64 targets are built for 64 KiB, which also runs on 4 and 16 KiB kernels.
- **Defaults are deliberate.** jemalloc purges freed pages only when that arena sees allocation activity, so a process with zero connections and no traffic keeps them (~25% of peak in the soak); `background_thread:true` returned them (717 → 196 MiB) but made no difference at a trough with live traffic, where the residue is pages pinned by surviving connections. If idle reclamation matters, enable it with `mallctl("background_thread")` after initialization — jemalloc documents that turning it on through `malloc_conf` at startup can deadlock.
- `allocator_tests::rust_allocations_come_from_jemalloc` asks jemalloc (`arenas.lookup`) whether a live `Box` is its own, which proves selection, not just linkage.

---

## Conventions

- All `#[napi]`-annotated items live in `src/proxy.rs`. Other modules are pure Rust with no napi imports.
- Background tasks (affinity eviction, IP state eviction) are spawned in `start()` and cancelled via the `shutdown_tx` broadcast channel.
- All counter decrements use RAII guards (`BalancerGuard`, `ActiveGuard`). Never decrement in a finally-style chain.
- `Relaxed` ordering for per-connection counters (active, accepted, errors). `AcqRel` only where cross-thread ordering is required — each such site has a comment explaining why.
- Error type: `SymphonyError` → `napi::Error` via `From`. No `unwrap()` on paths reachable from JS.
- `#![deny(clippy::all)]` is set in `lib.rs`. Fix clippy warnings before committing; run `cargo clippy --all-targets` as listed in Testing.

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

`cargo test` runs in CI and works for most of the crate, but `#[cfg(test)]` code must not
construct a struct that holds a `napi::bindgen_prelude::Buffer` field — directly (`JsCertConfig`,
`JsMtlsConfig`) or transitively (`JsRouteConfig`, `JsListenerConfig`, `JsResolveRoute`, and
anything that embeds one of those, e.g. `JsProxyConfig`, `JsHotConfig`) — even with that field
set to `None`. `Buffer`'s drop glue only links against a running Node host, which a standalone
`cargo test` binary doesn't have, so the link fails. Test pure/router-layer logic (structs
without `Buffer`, like `JsProtectionConfig`, already have `#[test]` coverage) with plain Rust
`#[test]`s, and exercise the `Buffer`-holding structs through the JS integration suite below
instead.

- **`util.ts`** — self-signed cert generation via `openssl` (or a fallback baked-in cert if openssl is unavailable), free-port helper, echo servers, TLS/TCP round-trip helpers
- **`proxy.spec.ts`** — TLS termination, wildcard SNI routing, `updateConfig` hot-swap, all-or-nothing `start()`, the default route
- **`protection.spec.ts`** — rate limit token bucket exhaustion, CIDR blocklist in `blockedIps()`, IPv4 clients of a `[::]` listener (skips where `net.ipv6.bindv6only=1`)
- **`server.spec.ts`** — the `symphony-server` bin as real processes: reloads, cert-file watching, `status.json` ownership, and an older process standing down (short `SYMPHONY_STATUS_POLL_MS` / `SYMPHONY_SUPERSEDE_GRACE_MS`, test-only env overrides)
- **`suspended.spec.ts`** — hold → resolve → proxy, hold → null → close, hold → timeout → drop
- **`mtls.spec.ts`** — mTLS termination + PROXY v2 TLV forwarding of the client cert chain (0xE2, SSL TLV 0x20); skips without openssl
- **`metrics.spec.ts`** — per-listener breakdown and byte counting, `renderPrometheus` output shape, the admin endpoint over UDS + TCP, and stale-socket reclaim after a `SIGKILL`
- **`failover.spec.ts`** — peer failover across two or three proxies in one process (UDS upstreams that record the PROXY v1 source); the client binds 127.0.0.2 so the forwarded client address differs from the forwarding node's. A route learns it is down only by losing one connection (`markDown`), as in production
- **`liveness.spec.ts`** — the half-close bound over a real passthrough proxy. Its client uses `allowHalfOpen: true` (otherwise Node answers the proxy's FIN with its own and there is no half-close to bound) and a synthetic `clientHello()` from `util.ts` (otherwise `peek()` blocks for its 5s reassembly timeout and a no-SNI connection resolves to no route)

The Rust toolchain is pinned to `1.94.1` in `rust-toolchain.toml`. Ensure rustup's
`~/.cargo/bin` (or `$CARGO_HOME/bin` with a custom Cargo home) is on `PATH` ahead of any
system-installed `cargo`, including in non-interactive shells. From the repository root,
`cargo --version` should report `1.94.1`; if the pinned toolchain is missing, run
`rustup toolchain install` from the repository root. This also applies to `npm run build:debug`,
which invokes Cargo.

Build the addon before running the Node tests, and repeat the build after Rust changes so the tests
load the current native addon:
```bash
npm run build:debug
npm test
```

`npm test` does not run the Rust checks below. For changes to Rust sources (`src/**`, `build.rs`),
Cargo manifests or lockfiles, or Rust toolchain/formatter configuration (`rust-toolchain.toml`,
`rustfmt.toml`), run these Rust CI checks before pushing:
```bash
cargo test
cargo clippy --all-targets
cargo fmt --check
```

CI runs these Rust checks on Linux (`ubuntu-latest`), and its result is authoritative. On macOS,
the Linux-only `#[cfg(target_os = "linux")]` branches are not compiled. Run `cargo test`
and `cargo clippy --all-targets` in a Linux environment before pushing from macOS. The [README Cross-compilation section](README.md#cross-compilation) documents the Linux Docker images.
`cargo fmt --check` can run on either platform.

Tests bind on random high ports (`port: 0`) to avoid conflicts. Suspended-route tests use short `suspendTimeoutMs` (200ms) to keep the suite fast.

---

## Non-obvious gotchas

- **The per-connection future is per-connection memory**: `handle`'s future is the tokio task allocated at accept and resident for the connection's life (~3.4 KiB), so it multiplies by the connection count. Await a large, rarely-taken future through `Box::pin` (the HTTP/1 rewriter is ~17 KiB). Moving a large value onward inside the future — into an async fn's arguments, out of a `match` scrutinee, into another async block — can leave its old slot reserved for the rest of the connection (an async fn keeps its arguments beside its working copy; a borrowed or partly-moved local keeps its slot until its scope ends). So the 1.2 KiB `TlsStream` is matched and passed by reference, `copy` is pinned where it is created, and the listeners spawn `handle(..)` itself rather than an `async move` wrapper around it. `proxy_conn::tests::the_per_connection_future_stays_within_budget` fails past 4 KiB under `cargo test` (the debug layout tracks release within a few dozen bytes); `RUSTC_BOOTSTRAP=1 RUSTFLAGS=-Zprint-type-sizes cargo build --release --lib` shows which field grew.
- **`copy_bidirectional` half-close**: it returns only once *both* directions have finished — an error or RST on either side ends the whole copy, but a clean EOF on one side does not. That asymmetry is why `liveness.rs` exists. The `ActiveGuard` drop handles both clean close and error paths.
- **Keepalive is set on the listening socket, not on accepted ones**: Linux copies `SOCK_KEEPOPEN` and the keepalive timings into each accepted socket and arms its timer (`tcp_create_openreq_child`), so `make_reuseport_socket` configures it once per worker instead of the accept path paying three `setsockopt` calls per connection. `liveness::tests::accepted_sockets_carry_the_configured_keepalive` is the guard: if a platform stops inheriting them, every connection silently loses dead-peer detection, which no round-trip test would notice.
- **The half-close bound arms on the client half's `poll_shutdown` completing, not on the upstream's read EOF**: those are different instants, and only the first one means the FIN is out. A `TlsStream` accepts writes into rustls' unbounded buffer and drains them during shutdown, so a clock started at the EOF runs against a flush still in progress and truncates the tail for a slow client. `liveness::tests::a_pending_client_shutdown_does_not_arm_the_bound` pins the ordering. A *client* EOF shuts down the write half to the *upstream* and arms nothing — bounding that would cut a client that legitimately `shutdown(SHUT_WR)`s after its request and then waits on a slow upstream.
- **Affinity bounds check**: after `updateConfig` shrinks the socket list, a stale affinity `socket_idx` may be out of bounds. `balancer.rs::pick()` always bounds-checks before using the affinity index and falls back to least-connections if out of range.
- **`resolveConnection` with unknown ID**: a no-op, not an error. The connection has already timed out and been dropped by the time JS calls this with a stale ID.
- **`ring` vs `md-5`**: `ring 0.17` removed MD5 support. JA3 fingerprints use `md-5 0.10` (RustCrypto). SHA-256 for cert deduplication still uses `ring::digest::SHA256` (ring is a direct dep for this).
- **musl RLIMIT_NOFILE**: musl hard limit is often 1048576. symphony logs a warning at startup if the requested limit exceeds the hard limit and uses the hard limit instead.
- **napi async methods must not take `&mut self`**: use `Mutex<>` for fields that need mutation after construction (currently `shutdown_tx: Mutex<Option<broadcast::Sender<()>>>`).
- **`JsUpstream` is a flat struct**: the TypeScript `Upstream` discriminated union is mapped to a single flat `JsUpstream { kind, host?, port?, path?, ipAffinity?, ipAffinityTtlMs? }` struct on the Rust side to avoid napi union complexity. Fields not relevant to a given `kind` will be `None`.
