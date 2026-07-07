# Symphony — deployment security & compliance notes

This document gives operators and reviewers the guidance that keeps coming up in
security questionnaires and compliance reviews: how Symphony handles private keys,
how to protect its configuration, why it links MD5, and what its TLS story is today
versus what is planned. It is deployment guidance, not a control catalog — Symphony
is an L4/TLS termination proxy, and the items below describe how to run it safely and
how to answer common questions about it.

---

## 1. Private key handling

Symphony never generates, stores, or manages key material of its own. Every private
key is supplied by the operator, either:

- **inline** as a PEM string/`Buffer` in `CertConfig` (`certChain` / `privateKey`), or
- **by path** in the standalone `symphony-server` config
  (`certChainFile` / `privateKeyFile`), resolved by the server before handing inline
  PEM to the native layer.

**In memory.** Once parsed, a private key lives only inside the rustls `ServerConfig`
for the routes that use it. The PEM buffer Symphony holds while building that config is
wrapped in `Zeroizing` (RustCrypto) and is zeroed on drop, so the raw PEM is not left
lingering in freed heap after the `ServerConfig` is built. Symphony does not log key
material and does not write keys back to disk.

**On disk (operator responsibility).** Key files are only as protected as the operator
makes them. Recommended baseline:

| Path | Owner | Mode | Notes |
|---|---|---|---|
| Private key files (`*-key.pem`) | the Symphony service user | `0600` | Never group/world readable. |
| Cert chain files (`*.pem`) | the Symphony service user | `0644` | Public material; readable is fine. |
| Directory holding keys | the Symphony service user | `0700` | Prevents directory listing / traversal by other users. |

- Run `symphony-server` as a dedicated **non-root** service user and grant that user
  ownership of the key directory. Only privileged ports (`:80`/`:443`) need elevated
  capability — prefer `CAP_NET_BIND_SERVICE` (e.g. systemd `AmbientCapabilities`) over
  running the whole process as root.
- Keep keys off shared/backed-up volumes unless those backups are themselves encrypted
  and access-controlled.

**Rotation.** `symphony-server` watches the cert/key files referenced by its config and
hot-reloads an in-place or renamed rotation live — no config write, no restart, no
dropped connections (see the cert-rotation notes in `CLAUDE.md`). To rotate a key:
replace the key and matching chain on disk (atomic rename preferred so a reader never
sees a half-written pair), and Symphony picks them up on the next debounced reconcile.
During the window between a new chain and its new key, the previous cert continues to
serve for that SNI (per-route cert failures are isolated and the last-good route is
carried forward), so a mismatched mid-rotation pair degrades one route briefly rather
than aborting the port set. Kubernetes projected-volume (`..data` symlink swap)
rotation is **not** yet covered by the file watcher.

> KMS/HSM-backed keys are intentionally out of scope today. Symphony consumes PEM only;
> if a hardware-custody requirement appears, it would be a new key-source integration,
> not a change to the handling above.

---

## 2. Configuration file integrity

The standalone `symphony-server` **watches its config file and hot-reloads on change**.
That is a deliberate operational feature (live route/cert updates), but it also means
that **anyone who can write the config file can redirect or intercept traffic** — change
an upstream, swap a cert, or drop a route — without restarting the process. The config
file is a traffic-control surface and should be protected accordingly.

Recommended controls:

- **Restrictive permissions.** Config file `0600` (or `0640` with a trusted operator
  group), owned by the Symphony service user; containing directory `0700`. No
  world-writable paths anywhere in the resolved config or cert/key paths.
- **File-integrity monitoring (FIM).** Put the config file — and the cert/key directory —
  under a FIM tool (AIDE, Tripwire, `auditd` watches, or the platform's equivalent) so
  an unexpected modification raises an alert. Because reloads are silent and
  connection-preserving, FIM is the primary detection for unauthorized config change.
- **Provenance.** Prefer generating the config from a controlled source (host-manager,
  config management, or an image build) rather than hand-editing in place, so the
  authoritative copy is versioned and any on-host drift is visible.
- **`status.json`.** `symphony-server` writes `status.json` (pid, version, bound ports)
  for supervisors. Treat it as attacker-influenceable state-out, not trusted input —
  it should not be writable by anyone who shouldn't already control the service.

---

## 3. MD5 in JA3 — why the dependency scanner flag is a false positive

Symphony computes a **JA3** TLS client fingerprint in the ClientHello peek path
(`src/sni.rs`), and JA3 is *defined* by its spec as the **MD5** of a canonicalized
ClientHello string. That is the only reason an MD5 implementation appears in the
dependency tree.

**This is not a cryptographic use of MD5.** JA3 uses MD5 purely as a fixed-length
*label* to identify and correlate a client's TLS stack. It is not used for integrity,
authentication, key derivation, signatures, or confidentiality — nothing about
Symphony's security depends on MD5 being collision- or preimage-resistant. An attacker
who could forge an MD5 collision would gain nothing except the ability to make two
different ClientHellos share a fingerprint, which is already possible by other means and
is exactly why JA3 is treated as a coarse signal, not an authorization primitive.

Because of that coarseness (Chrome and other Chromium browsers randomize ClientHello
extension order, so one client emits many JA3 hashes), Symphony also computes **JA4**,
the randomization-resistant successor, which uses a **truncated SHA-256** — again as an
identity label, not a security primitive. Both fingerprints feed optional blocklists
(`ja3Blocklist` / `ja4Blocklist`); neither is a trust boundary.

**Questionnaire answer:** *Symphony links an MD5 implementation solely because the JA3
TLS-fingerprint standard is defined over MD5. MD5 is used as a non-cryptographic
identity/labeling hash for client fingerprinting and blocklist matching. It is not used
for any integrity, authentication, signing, or confidentiality function, so the standard
MD5-weakness findings do not apply.*

---

## 4. TLS parameter attestation (planned)

**Today.** Symphony terminates TLS with **rustls 0.23** using the **`ring`**
CryptoProvider (`tls12` feature enabled), which negotiates **TLS 1.2 and TLS 1.3** with
rustls's default cipher suites and key-exchange groups. Symphony does **not** currently
expose configuration for minimum protocol version, cipher suites, or key-exchange
groups, and does **not** report the negotiated parameters through its metrics API. The
effective policy is "rustls defaults," which are modern and safe but are attested today
only by pointing at the rustls/`ring` versions in the lockfile.

**Why this matters for compliance.** **PCI DSS 12.3.3** requires customers to formally
review, at least annually, the cryptographic cipher suites and protocols in use and
confirm none are deprecated. Meeting that cleanly means Symphony should eventually be
able to *report* its negotiated/configured TLS parameters as machine-readable evidence,
rather than the customer inferring them from dependency versions.

**Planned direction (design note, keep options open):**

- Add a way to **report** the active TLS configuration (min version, offered suites,
  key-exchange groups) — e.g. via the metrics/status surface — so it can be attached to
  an annual review as evidence.
- Consider making **minimum TLS version** (and optionally a suite policy) configurable
  per listener, so operators can raise the floor to TLS 1.3 where their clients allow.
- **FIPS 140-3:** rustls supports a FIPS-validated path via the **`aws-lc-rs`**
  CryptoProvider. Keeping a provider swap cheap now (avoid hard-coding `ring`-only
  assumptions in new code) preserves the option for government/regulated customers
  later. Note the swap is not entirely free: Symphony currently calls into `ring`
  explicitly in two non-negotiation spots — the TLS session `Ticketer` and the cert
  dedup SHA-256 in `src/tls.rs` — plus JA3's `md-5`; those call sites would need to move
  to the chosen provider's primitives as part of any FIPS build.

None of item 4 is implemented yet; it is recorded here so the design stays open and so
reviewers get a consistent answer about the current state versus the roadmap.

---

## 5. DDoS — shared responsibility

Symphony is **not** a volumetric DDoS mitigation layer, and deployments should not treat
it as one.

- **Out of scope: L3/L4 volumetric attacks** (SYN floods, UDP/amplification floods, raw
  bandwidth exhaustion). Absorbing these is the responsibility of the **upstream network
  provider / cloud edge** (scrubbing centers, anycast, provider-level rate limiting)
  that sits in front of Symphony. Symphony runs on a host and inherits that host's
  network capacity; it cannot defend against traffic that saturates the link before it
  arrives.
- **In scope: connection-level controls.** Once connections reach it, Symphony provides
  per-IP connection rate limiting and burst caps, per-IP concurrency limits, CIDR
  allow/blocklists, TLS-handshake timeouts (to shed slow-handshake abuse), `requireSni`
  enforcement, and JA3/JA4 fingerprint blocking. These blunt application-adjacent and
  connection-exhaustion abuse and keep one noisy source from starving others — they are
  **not** a substitute for upstream volumetric protection.

**Questionnaire answer:** *Volumetric (L3/L4) DDoS protection is a shared responsibility:
absorbing bandwidth/packet floods is handled by the upstream network/cloud provider in
front of Symphony. Symphony contributes connection-level controls — per-IP rate and
concurrency limits, CIDR filtering, handshake timeouts, SNI enforcement, and fingerprint
blocklists — to mitigate connection-exhaustion and abuse for traffic that reaches it.*
