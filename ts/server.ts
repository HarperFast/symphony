#!/usr/bin/env node
import { readFileSync, readlinkSync, writeFileSync, renameSync, unlinkSync, watch } from 'node:fs';
import { dirname, isAbsolute, join, basename, resolve } from 'node:path';
import { performance } from 'node:perf_hooks';
import { SymphonyProxy } from './index.js';
import type { ProxyConfig, ListenerConfig, RouteConfig, CertConfig, MtlsConfig } from './index.js';
import { AdminServer, type AdminConfig, type MetricsSnapshot } from './admin.js';

// package.json sits at the package root, which is 1 level above dist/server.js (production
// layout) or 2 levels above dist-test/ts/server.js (test layout) — try both, like loadAddon.
function readVersion(): string {
	for (const rel of [['..'], ['..', '..'], ['..', '..', '..']]) {
		try {
			return (JSON.parse(readFileSync(join(__dirname, ...rel, 'package.json'), 'utf8')) as { version: string }).version;
		} catch {
			// try next depth
		}
	}
	return '0.0.0';
}
const pkg = { version: readVersion() };

// ── Config-file types (a small superset of the napi config) ─────────────────────
// The standalone server accepts cert material either inline (PEM string) or by file
// path. host-manager writes public cert chains inline but references private keys by
// path, so private keys stay out of the config file. The napi CertConfig only knows
// about inline material, so we resolve file paths here before constructing the proxy.

interface FileCertConfig {
	certChain?: string;
	certChainFile?: string;
	privateKey?: string;
	privateKeyFile?: string;
}

interface FileMtlsConfig {
	clientCaCert?: string;
	clientCaCertFile?: string;
	requireClientCert?: boolean;
}

type FileRouteConfig = Omit<RouteConfig, 'cert' | 'mtls'> & {
	cert?: FileCertConfig;
	mtls?: FileMtlsConfig;
};

type FileListenerConfig = Omit<ListenerConfig, 'defaultCert' | 'mtls'> & {
	defaultCert?: FileCertConfig;
	mtls?: FileMtlsConfig;
};

interface FileProxyConfig {
	listeners: FileListenerConfig[];
	routes: FileRouteConfig[];
	workerThreads?: number;
	readBufferSize?: number;
	clientReadBufferSize?: number;
	upstreamReadBufferSize?: number;
	tcpKeepalive?: ProxyConfig['tcpKeepalive'];
	halfCloseTimeoutMs?: number;
}

interface ConfigFile {
	version?: number;
	/** Optional read-only metrics/health endpoint. Omit to expose nothing. */
	admin?: AdminConfig;
	proxies: FileProxyConfig[];
}

function log(msg: string, ...rest: unknown[]): void {
	console.log(`${new Date().toISOString()} [symphony-server] ${msg}`, ...rest);
}
function logErr(msg: string, ...rest: unknown[]): void {
	console.error(`${new Date().toISOString()} [symphony-server] ${msg}`, ...rest);
}

function resolvePath(p: string, baseDir: string): string {
	return isAbsolute(p) ? p : join(baseDir, p);
}

function resolveCert(c: FileCertConfig, baseDir: string): CertConfig {
	const certChain =
		c.certChain ?? (c.certChainFile ? readFileSync(resolvePath(c.certChainFile, baseDir), 'utf8') : undefined);
	const privateKey =
		c.privateKey ?? (c.privateKeyFile ? readFileSync(resolvePath(c.privateKeyFile, baseDir)) : undefined);
	if (certChain === undefined || privateKey === undefined) {
		throw new Error('route cert requires both a chain (certChain/certChainFile) and a key (privateKey/privateKeyFile)');
	}
	return { certChain, privateKey };
}

function resolveMtls(m: FileMtlsConfig, baseDir: string): MtlsConfig {
	const clientCaCert =
		m.clientCaCert ?? (m.clientCaCertFile ? readFileSync(resolvePath(m.clientCaCertFile, baseDir), 'utf8') : undefined);
	if (clientCaCert === undefined) {
		throw new Error('route mtls requires a client CA (clientCaCert/clientCaCertFile)');
	}
	return { clientCaCert, requireClientCert: m.requireClientCert };
}

// A cert the Rust layer is guaranteed to reject at build time (empty PEM → "no
// certificates"). Substituted for a route whose cert/key file can't be read, so the failure
// is isolated inside build_route_table (which carries the route's last-good forward on a
// hot-swap while its client-cert policy is unchanged, or drops just that SNI) instead of throwing out of
// toProxyConfig and aborting the update for every route on the port-set.
const UNRESOLVABLE_CERT: CertConfig = { certChain: '', privateKey: Buffer.alloc(0) };

// Stands in for a client CA that can't be read: the requested policy is unknown. No verifier builds
// from an empty bundle, so on a terminating route it never matches a serving route's policy and the
// route is dropped rather than kept under its old one. A passthrough route ignores mtls.
const UNRESOLVABLE_MTLS: MtlsConfig = { clientCaCert: '', requireClientCert: true };

// Resolve one route's cert/mTLS from disk, isolating a file-read failure (e.g. ENOENT while a
// cert rotates) to this route rather than letting it abort the whole port-set's reconcile.
function resolveRoute(r: FileRouteConfig, baseDir: string): RouteConfig {
	let mtls: MtlsConfig | undefined;
	try {
		mtls = r.mtls ? resolveMtls(r.mtls, baseDir) : undefined;
	} catch (err) {
		logErr(`failed to resolve the client CA for route '${r.sni}' — isolating route:`, (err as Error).message);
		return { ...r, cert: UNRESOLVABLE_CERT, mtls: UNRESOLVABLE_MTLS };
	}
	try {
		return { ...r, cert: r.cert ? resolveCert(r.cert, baseDir) : undefined, mtls };
	} catch (err) {
		logErr(`failed to resolve cert material for route '${r.sni}' — isolating route:`, (err as Error).message);
		return { ...r, cert: UNRESOLVABLE_CERT, mtls };
	}
}

// Resolve a file-backed proxy spec into the in-memory ProxyConfig the napi layer accepts. A
// listener-level cert failure is intentionally *not* isolated here — it throws, so the
// per-proxy guard in doReconcile leaves the existing proxy running rather than recreating it
// against an unbuildable default cert.
function toProxyConfig(spec: FileProxyConfig, baseDir: string): ProxyConfig {
	const listeners: ListenerConfig[] = spec.listeners.map((l) => ({
		...l,
		defaultCert: l.defaultCert ? resolveCert(l.defaultCert, baseDir) : undefined,
		mtls: l.mtls ? resolveMtls(l.mtls, baseDir) : undefined,
	}));
	const routes: RouteConfig[] = spec.routes.map((r) => resolveRoute(r, baseDir));
	return {
		listeners,
		routes,
		workerThreads: spec.workerThreads,
		readBufferSize: spec.readBufferSize,
		clientReadBufferSize: spec.clientReadBufferSize,
		upstreamReadBufferSize: spec.upstreamReadBufferSize,
		tcpKeepalive: spec.tcpKeepalive,
		halfCloseTimeoutMs: spec.halfCloseTimeoutMs,
	};
}

// Sorted listener ports identify a proxy across reloads (the route table is per-proxy,
// so each external port keeps its own SymphonyProxy — matching host-manager's model).
function portKey(listeners: { port: number }[]): string {
	return listeners
		.map((l) => l.port)
		.sort((a, b) => a - b)
		.join(',');
}

// Whether a pid is a running process started as this user with `--config <configPath>`. `verified`
// reads its argv, working directory and run state from /proc, which also keeps a recycled pid, a
// stopped process or a zombie from counting; `unverified` is liveness alone, where there is no /proc.
function servesConfig(pid: number, configPath: string): 'verified' | 'unverified' | 'no' {
	try {
		process.kill(pid, 0);
	} catch {
		return 'no';
	}
	let argv: string[];
	let cwd: string;
	try {
		argv = readFileSync(`/proc/${pid}/cmdline`, 'utf8').split('\0');
		cwd = readlinkSync(`/proc/${pid}/cwd`);
	} catch {
		return process.platform === 'linux' ? 'no' : 'unverified';
	}
	if ('TtZX'.includes(procStat(pid)?.state ?? 'X')) return 'no';
	const match = argv.some(
		(arg, i) => (arg === '--config' || arg === '-c') && i + 1 < argv.length && resolve(cwd, argv[i + 1]) === configPath
	);
	return match ? 'verified' : 'no';
}

interface StatusOwner {
	pid: number;
	startedAt: string;
	configPath?: string;
	ports?: number[];
	/** `host:port` of every listener the owner has bound. Absent from a pre-1.5 status. */
	listeners?: string[];
}

// Run state and boot-relative start time (clock ticks) from /proc/<pid>/stat.
function procStat(pid: number): { state: string; startTicks: number } | undefined {
	try {
		const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
		const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
		return { state: fields[0], startTicks: Number(fields[19]) };
	} catch {
		return undefined;
	}
}

function endpoint(l: { host?: string; port: number }): string {
	return `${l.host ?? '0.0.0.0'}:${l.port}`;
}

// The newest process owns status.json; pid breaks a same-millisecond tie.
function startedAfter(a: StatusOwner, b: StatusOwner): boolean {
	const aStart = Date.parse(a.startedAt);
	const bStart = Date.parse(b.startedAt);
	return aStart > bStart || (aStart === bStart && a.pid > b.pid);
}

// Test-only overrides, bounded so a bad value can't turn a timer into a busy loop.
function durationFromEnv(name: string, fallback: number): number {
	const raw = process.env[name];
	if (raw === undefined) return fallback;
	const ms = Number(raw);
	if (Number.isSafeInteger(ms) && ms >= 1 && ms <= 600_000) return ms;
	logErr(`ignoring ${name}=${raw}: expected whole milliseconds in [1, 600000]`);
	return fallback;
}

const STATUS_POLL_MS = durationFromEnv('SYMPHONY_STATUS_POLL_MS', 1_000);
// Longer than host-manager's reap of a failed successor (SIGTERM, then SIGKILL after 5 s), so a
// successor being reaped is seen to exit before this process gives up its listeners.
const SUPERSEDE_GRACE_MS = durationFromEnv('SYMPHONY_SUPERSEDE_GRACE_MS', 10_000);

interface ActiveProxy {
	proxy: SymphonyProxy;
	constructionSig: string;
	endpoints: string[];
}

class ServerState {
	private readonly configPath: string;
	private readonly statusPath: string;
	private readonly baseDir: string;
	private readonly active = new Map<string, ActiveProxy>();
	private readonly admin: AdminServer;
	private startedAt = '';
	private reloadedAt = '';
	private reloading: Promise<void> = Promise.resolve();
	private watcher: ReturnType<typeof watch> | null = null;
	// Cert/key files referenced by the current config, watched for rotation. Keyed by
	// parent directory (one fs.watch per dir, deduped) → the set of basenames we care about
	// in that dir, so an unrelated file change in the same dir is ignored.
	private readonly certWatchers = new Map<string, ReturnType<typeof watch>>();
	private certFilesByDir = new Map<string, Set<string>>();
	private debounceTimer: NodeJS.Timeout | null = null;
	private statusRecheck: NodeJS.Timeout | null = null;
	private yieldedTo: number | null = null;
	private supersededBy: { pid: number; startedAt: string; since: number } | null = null;
	private standDownBlocked: string | null = null;
	private claimHeld: string | null = null;
	private readonly onSuperseded: (pid: number) => void;
	private stopping = false;

	constructor(configPath: string, statusPath: string, onSuperseded: (pid: number) => void) {
		this.configPath = configPath;
		this.statusPath = statusPath;
		this.onSuperseded = onSuperseded;
		this.baseDir = dirname(configPath);
		this.admin = new AdminServer(() => this.metricsSnapshot(), log, logErr);
	}

	// Read live on each request rather than cached, so a scrape never serves counters frozen at
	// the last reconcile.
	private metricsSnapshot(): MetricsSnapshot {
		return {
			pid: process.pid,
			version: pkg.version,
			startedAt: this.startedAt,
			reloadedAt: this.reloadedAt,
			proxies: [...this.active].map(([ports, entry]) => ({ ports, metrics: entry.proxy.metrics() })),
		};
	}

	private readConfig(): ConfigFile | null {
		let raw: string;
		try {
			raw = readFileSync(this.configPath, 'utf8');
		} catch (err) {
			logErr(`could not read config ${this.configPath}:`, (err as Error).message);
			return null;
		}
		try {
			const parsed = JSON.parse(raw) as ConfigFile;
			if (!parsed || !Array.isArray(parsed.proxies)) {
				logErr('config has no "proxies" array — ignoring');
				return null;
			}
			return parsed;
		} catch (err) {
			logErr('config is not valid JSON (ignoring, keeping current routes):', (err as Error).message);
			return null;
		}
	}

	// Serialize reconciles so overlapping fs events / SIGHUP can't interleave start/stop.
	reconcile(): Promise<void> {
		this.reloading = this.reloading.then(() => this.doReconcile()).catch((err) => logErr('reconcile failed:', err));
		return this.reloading;
	}

	// Debounce and coalesce fs events (config or cert files) into a single reconcile. The
	// reconcile itself is serialized via `this.reloading`, so bursts collapse to one reload.
	private scheduleReconcile(): void {
		if (this.debounceTimer) clearTimeout(this.debounceTimer);
		this.debounceTimer = setTimeout(() => {
			this.debounceTimer = null;
			void this.reconcile();
		}, 300);
	}

	// Collect the cert/key files referenced by the current config, grouped by parent
	// directory. Inline cert material (certChain/privateKey) has no file and is skipped.
	private collectCertFiles(config: ConfigFile): Map<string, Set<string>> {
		const byDir = new Map<string, Set<string>>();
		const add = (p: string | undefined): void => {
			if (!p) return;
			const abs = resolvePath(p, this.baseDir);
			const dir = dirname(abs);
			let set = byDir.get(dir);
			if (!set) byDir.set(dir, (set = new Set<string>()));
			set.add(basename(abs));
		};
		for (const proxy of config.proxies) {
			for (const l of proxy.listeners ?? []) {
				add(l.defaultCert?.certChainFile);
				add(l.defaultCert?.privateKeyFile);
				add(l.mtls?.clientCaCertFile);
			}
			for (const r of proxy.routes ?? []) {
				add(r.cert?.certChainFile);
				add(r.cert?.privateKeyFile);
				add(r.mtls?.clientCaCertFile);
			}
		}
		return byDir;
	}

	// Reconcile the set of cert-file watchers against the current config: drop watchers for
	// directories no longer referenced (so we don't leak them across reloads) and add one
	// per newly-referenced directory. Watchers filter events against the live
	// `certFilesByDir` set, so a config change that repoints cert files is honored without
	// recreating the watcher.
	private updateCertWatchers(config: ConfigFile): void {
		const desired = this.collectCertFiles(config);
		this.certFilesByDir = desired;

		for (const [dir, w] of this.certWatchers) {
			if (!desired.has(dir)) {
				w.close();
				this.certWatchers.delete(dir);
			}
		}

		for (const dir of desired.keys()) {
			if (this.certWatchers.has(dir)) continue;
			let w: ReturnType<typeof watch>;
			try {
				w = watch(dir, (_event, filename) => {
					// Ignore changes to files in this dir we don't reference (temp files, other
					// tenants' unrelated material). A null filename (rare, platform-specific)
					// falls through to a reconcile.
					if (filename && !this.certFilesByDir.get(dir)?.has(filename)) return;
					this.scheduleReconcile();
				});
			} catch (err) {
				logErr(`could not watch cert directory ${dir}:`, (err as Error).message);
				continue;
			}
			// Without an 'error' listener an fs.watch error would throw as an unhandled exception.
			w.on('error', (err) => logErr(`cert watcher error (${dir}):`, err));
			this.certWatchers.set(dir, w);
		}
	}

	private async doReconcile(): Promise<void> {
		const config = this.readConfig();
		if (!config) return;

		const seen = new Set<string>();
		for (const spec of config.proxies) {
			const key = portKey(spec.listeners);
			seen.add(key);
			const existing = this.active.get(key);
			// Guard the whole per-proxy reconcile — cert resolution, construction, and start().
			// A failure here (unreadable cert file, listener bind error) must skip only this
			// port-set and leave any already-running proxy for it untouched, not abort the loop
			// and skip every remaining port-set. `seen` already holds `key`, so a skipped
			// existing proxy is not torn down by the removal pass below.
			try {
				const proxyConfig = toProxyConfig(spec, this.baseDir);
				// Signature over the *resolved* listeners (cert/key/CA contents included), not the
				// raw spec: the listener-level default cert is frozen at construction (Rust
				// default_listener_tls), so updateConfig can't hot-swap it. Keying off resolved
				// content means a listener-cert rotation on disk (same paths, new bytes) changes
				// the signature and forces a recreate, which route-only hot-swap would miss.
				//
				// Protection PRESENCE (hasProtection) is part of the signature: none→some and
				// some→none transitions force a seamless recreate so the new listener is
				// constructed with the correct Option<ProtectionState>. Protection CONTENTS are
				// excluded so a contents-only change stays on the hot-swap path without recreating.
				// failoverIngress follows the same rule: presence recreates, trustedSources hot-swaps.
				//
				// The proxy-level fields below are frozen at construction on the Rust side too, and
				// updateConfig reaches neither: without them in the signature, editing only a buffer
				// size (or workerThreads) leaves the sig unchanged, so the reload takes the hot-swap
				// branch, reports success, and keeps running the old value.
				const constructionSig = JSON.stringify({
					listeners: proxyConfig.listeners.map(({ protection, failoverIngress, ...rest }) => ({
						...rest,
						hasProtection: protection != null,
						isFailoverIngress: failoverIngress != null,
					})),
					workerThreads: proxyConfig.workerThreads,
					readBufferSize: proxyConfig.readBufferSize,
					clientReadBufferSize: proxyConfig.clientReadBufferSize,
					upstreamReadBufferSize: proxyConfig.upstreamReadBufferSize,
					tcpKeepalive: proxyConfig.tcpKeepalive,
					halfCloseTimeoutMs: proxyConfig.halfCloseTimeoutMs,
				});
				if (existing && existing.constructionSig === constructionSig) {
					// Same listeners (presence-unchanged) → hot-swap routes and protection contents.
					// All listeners here either had protection from the start (Some) or never did
					// (None, excluded by filter). none→some / some→none went through the recreate path.
					existing.proxy.updateConfig({
						routes: proxyConfig.routes,
						protection: proxyConfig.listeners
							.filter((l) => l.protection != null)
							.map((l) => ({ port: l.port, protection: l.protection! })),
						failoverIngress: proxyConfig.listeners
							.filter((l) => l.failoverIngress != null)
							.map((l) => ({ port: l.port, trustedSources: l.failoverIngress!.trustedSources })),
					});
				} else {
					// New port-set, or a construction-frozen setting changed → (re)create. SO_REUSEPORT lets the
					// new listener bind before the old one is dropped, so there is no bind gap.
					const proxy = new SymphonyProxy(proxyConfig);
					proxy.on('error', (err, ctx) =>
						logErr(`proxy [${key}] error${ctx?.listener ? ` (${ctx.listener})` : ''}:`, err)
					);
					await proxy.start();
					if (existing) await existing.proxy.stop().catch((err) => logErr(`stopping old proxy [${key}]:`, err));
					this.active.set(key, { proxy, constructionSig, endpoints: proxyConfig.listeners.map(endpoint) });
					log(`proxy listening on ports [${key}]`);
				}
			} catch (err) {
				logErr(
					`failed to (re)configure proxy [${key}] — skipping, leaving any running listener in place:`,
					(err as Error).message
				);
			}
		}

		// Drop proxies whose port-set is no longer in the config.
		for (const [key, entry] of this.active) {
			if (!seen.has(key)) {
				await entry.proxy.stop().catch((err) => logErr(`stopping removed proxy [${key}]:`, err));
				this.active.delete(key);
				log(`proxy on ports [${key}] removed`);
			}
		}

		// Re-derive which cert/key files to watch from the config we just applied, so a
		// renewal on disk (no config.json write) triggers a reconcile and live reload.
		this.updateCertWatchers(config);

		// Rebinds only if the admin block changed. Never throws — the endpoint is
		// observability, and losing it must not abort a reconcile that already applied routes.
		const admin = config.admin && {
			...config.admin,
			socketPath: config.admin.socketPath ? resolvePath(config.admin.socketPath, this.baseDir) : undefined,
		};
		await this.admin.update(admin).catch((err) => logErr('admin endpoint update failed:', (err as Error).message));

		this.reloadedAt = new Date().toISOString();
		this.writeStatus();
	}

	private readStatusOwner(): StatusOwner | null {
		try {
			const { pid, startedAt, configPath, ports, listeners } = JSON.parse(readFileSync(this.statusPath, 'utf8')) ?? {};
			if (typeof pid !== 'number' || typeof startedAt !== 'string') return null;
			return {
				pid,
				startedAt,
				configPath: typeof configPath === 'string' ? configPath : undefined,
				ports: Array.isArray(ports) && ports.every((p) => typeof p === 'number') ? ports : undefined,
				listeners: Array.isArray(listeners) && listeners.every((l) => typeof l === 'string') ? listeners : undefined,
			};
		} catch {
			return null;
		}
	}

	private endpoints(): string[] {
		return [...this.active.values()].flatMap((entry) => entry.endpoints);
	}

	// During an overlapped upgrade both processes reload on the same config write. The outgoing one
	// must not point status.json back at itself, or a supervisor waiting for the successor's pid never
	// sees it.
	private writeStatus(): void {
		if (this.stopping) return;
		const owner = this.readStatusOwner();
		const peer = owner && owner.pid !== process.pid ? owner : null;
		const identity =
			peer && (peer.configPath === undefined || peer.configPath === this.configPath)
				? servesConfig(peer.pid, this.configPath)
				: 'no';
		if (peer && identity !== 'no' && startedAfter(peer, { pid: process.pid, startedAt: this.startedAt })) {
			if (this.yieldedTo !== peer.pid) log(`status.json belongs to newer pid ${peer.pid}; not overwriting it`);
			this.yieldedTo = peer.pid;
			this.considerStandingDown(peer, identity === 'verified');
			// Keep looking: if the successor exits while this process still serves, take the file back.
			this.recheckStatus();
			return;
		}
		this.yieldedTo = null;
		this.supersededBy = null;
		this.standDownBlocked = null;
		// A supervisor retires the process status.json named before as soon as it names this one, so
		// claiming it from a live owner with a listener this process lacks (a cert it could not read,
		// say) would leave that listener with nothing serving it.
		// A 1.4.0 or earlier owner lists only port numbers.
		const endpoints = this.endpoints();
		const ports = [...this.active.keys()].flatMap((k) => k.split(',').map(Number));
		const uncovered =
			!peer || identity === 'no'
				? []
				: peer.listeners
					? peer.listeners.filter((e) => !endpoints.includes(e))
					: (peer.ports ?? []).filter((p) => !ports.includes(p)).map((p) => `port ${p}`);
		if (uncovered.length) {
			const held = `pid ${peer!.pid} listens on ${uncovered.join(', ')}, which this process does not`;
			if (this.claimHeld !== held) log(`not taking status.json: ${held}`);
			this.claimHeld = held;
			this.recheckStatus();
			return;
		}
		this.claimHeld = null;
		const status = {
			pid: process.pid,
			version: pkg.version,
			startedAt: this.startedAt,
			reloadedAt: this.reloadedAt,
			configPath: this.configPath,
			ports,
			listeners: endpoints,
		};
		// Atomic write (temp + rename): the status file is rewritten on every reload, and a
		// supervisor polling it concurrently must never read a half-written document. An overlapping
		// peer writes the same file, hence the per-pid temp name.
		const tmp = `${this.statusPath}.${process.pid}.tmp`;
		try {
			writeFileSync(tmp, JSON.stringify(status, null, 2));
			renameSync(tmp, this.statusPath);
		} catch (err) {
			logErr(`could not write status ${this.statusPath}:`, (err as Error).message);
			try {
				unlinkSync(tmp);
			} catch {
				// never created, or already renamed into place
			}
		}
		this.recheckStatus();
	}

	// symphony#53: both processes accept on the same SO_REUSEPORT ports until one exits.
	private considerStandingDown(owner: StatusOwner, verified: boolean): void {
		const missing = owner.listeners ? this.endpoints().filter((e) => !owner.listeners!.includes(e)) : [];
		const ownStart = procStat(process.pid)?.startTicks;
		const ownerStart = procStat(owner.pid)?.startTicks;
		// startedAt is wall-clock, which a step backward can reorder; boot-relative ticks can't be.
		const startedLater =
			ownStart !== undefined &&
			ownerStart !== undefined &&
			(ownerStart > ownStart || (ownerStart === ownStart && owner.pid > process.pid));
		const blocked = !verified
			? 'its identity cannot be verified without /proc'
			: !startedLater
				? 'it did not start after this process'
				: owner.configPath !== this.configPath
					? 'its status names a different config'
					: !owner.listeners
						? 'its status does not list its listeners'
						: missing.length
							? `it is not listening on ${missing.join(', ')}`
							: null;
		if (blocked) {
			if (this.standDownBlocked !== blocked) log(`not standing down for pid ${owner.pid}: ${blocked}`);
			this.standDownBlocked = blocked;
			this.supersededBy = null;
			return;
		}
		this.standDownBlocked = null;
		const now = performance.now();
		if (this.supersededBy?.pid !== owner.pid || this.supersededBy.startedAt !== owner.startedAt) {
			this.supersededBy = { pid: owner.pid, startedAt: owner.startedAt, since: now };
			log(
				`pid ${owner.pid} serves this config on every listener; stopping in ${SUPERSEDE_GRACE_MS} ms unless it exits`
			);
			return;
		}
		if (now - this.supersededBy.since >= SUPERSEDE_GRACE_MS) this.onSuperseded(owner.pid);
	}

	private recheckStatus(): void {
		if (this.statusRecheck) clearTimeout(this.statusRecheck);
		this.statusRecheck = null;
		if (this.stopping) return;
		this.statusRecheck = setTimeout(() => {
			this.statusRecheck = null;
			// Queued behind any reconcile, so a rewrite never publishes a half-applied port set.
			void this.reloading
				.then(() => {
					if (this.stopping) return;
					if (this.readStatusOwner()?.pid === process.pid) {
						this.supersededBy = null;
						this.recheckStatus();
					} else {
						this.writeStatus();
					}
				})
				.catch((err) => {
					logErr('status check failed:', err);
					this.recheckStatus();
				});
		}, STATUS_POLL_MS);
		this.statusRecheck.unref();
	}

	async start(): Promise<void> {
		this.startedAt = new Date().toISOString();
		await this.reconcile();
		// Watch the directory (not the file) so atomic temp+rename writes keep firing events.
		const base = basename(this.configPath);
		this.watcher = watch(this.baseDir, (_event, filename) => {
			if (filename && filename !== base) return;
			this.scheduleReconcile();
		});
		// Without an 'error' listener an fs.watch error would throw as an unhandled exception.
		this.watcher.on('error', (err) => logErr('config watcher error:', err));
		log(`watching ${this.configPath} for changes`);
	}

	async stop(): Promise<void> {
		this.stopping = true;
		if (this.statusRecheck) {
			clearTimeout(this.statusRecheck);
			this.statusRecheck = null;
		}
		if (this.debounceTimer) {
			clearTimeout(this.debounceTimer);
			this.debounceTimer = null;
		}
		if (this.watcher) {
			this.watcher.close();
			this.watcher = null;
		}
		for (const w of this.certWatchers.values()) w.close();
		this.certWatchers.clear();
		await this.admin.stop().catch((err) => logErr('stopping admin endpoint:', (err as Error).message));
		await this.reloading.catch(() => {});
		for (const [key, entry] of this.active) {
			await entry.proxy.stop().catch((err) => logErr(`stopping proxy [${key}]:`, err));
		}
		this.active.clear();
		// status.json stays in place: a supervisor reads a dead pid as not running, and a successor can
		// rename its own status over the path between any ownership check here and an unlink.
	}
}

function parseArgs(argv: string[]): { config?: string; status?: string; version?: boolean; help?: boolean } {
	const out: { config?: string; status?: string; version?: boolean; help?: boolean } = {};
	for (let i = 0; i < argv.length; i++) {
		const a = argv[i];
		if (a === '--version' || a === '-v') out.version = true;
		else if (a === '--help' || a === '-h') out.help = true;
		else if (a === '--config' || a === '-c') out.config = argv[++i];
		else if (a === '--status' || a === '-s') out.status = argv[++i];
	}
	return out;
}

const USAGE = `symphony-server — standalone SNI-routing TLS proxy

Usage: symphony-server --config <path> [--status <path>]

Options:
  -c, --config <path>   Path to the JSON config file (required). Watched for live reload.
  -s, --status <path>   Path to write the status file. Default: <config-dir>/status.json
  -v, --version         Print the symphony version and exit.
  -h, --help            Show this help.

Signals:
  SIGHUP                Reload the config file immediately.
  SIGTERM, SIGINT       Gracefully stop all listeners and exit.`;

async function main(): Promise<void> {
	const args = parseArgs(process.argv.slice(2));
	if (args.version) {
		process.stdout.write(`${pkg.version}\n`);
		return;
	}
	if (args.help || !args.config) {
		process.stdout.write(`${USAGE}\n`);
		process.exit(args.help ? 0 : 1);
	}

	const configPath = resolve(args.config!);
	const statusPath = args.status ? resolve(args.status) : join(dirname(configPath), 'status.json');

	let shuttingDown = false;
	const shutdown = (reason: string) => {
		if (shuttingDown) return;
		shuttingDown = true;
		log(`${reason}, shutting down`);
		state
			.stop()
			.then(() => process.exit(0))
			.catch((err) => {
				logErr('error during shutdown:', err);
				process.exit(1);
			});
	};
	const state = new ServerState(configPath, statusPath, (pid) => shutdown(`superseded by pid ${pid}`));
	log(`symphony-server v${pkg.version} starting (pid ${process.pid})`);
	await state.start();

	process.on('SIGTERM', () => shutdown('received SIGTERM'));
	process.on('SIGINT', () => shutdown('received SIGINT'));
	process.on('SIGHUP', () => {
		log('received SIGHUP, reloading config');
		void state.reconcile();
	});
	process.on('unhandledRejection', (err) => logErr('unhandledRejection:', err));
}

main().catch((err) => {
	logErr('fatal:', err);
	process.exit(1);
});
