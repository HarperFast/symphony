#!/usr/bin/env node
import { readFileSync, writeFileSync, renameSync, unlinkSync, watch } from 'node:fs';
import { dirname, isAbsolute, join, basename } from 'node:path';
import { SymphonyProxy } from './index.js';
import type { ProxyConfig, ListenerConfig, RouteConfig, CertConfig, MtlsConfig } from './index.js';

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
}

interface ConfigFile {
	version?: number;
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
// hot-swap, or drops just that SNI on an initial build) instead of throwing out of
// toProxyConfig and aborting the update for every route on the port-set.
const UNRESOLVABLE_CERT: CertConfig = { certChain: '', privateKey: Buffer.alloc(0) };

// Resolve one route's cert/mTLS from disk, isolating a file-read failure (e.g. ENOENT while a
// cert rotates) to this route rather than letting it abort the whole port-set's reconcile.
function resolveRoute(r: FileRouteConfig, baseDir: string): RouteConfig {
	try {
		return {
			...r,
			cert: r.cert ? resolveCert(r.cert, baseDir) : undefined,
			mtls: r.mtls ? resolveMtls(r.mtls, baseDir) : undefined,
		};
	} catch (err) {
		logErr(`failed to resolve cert material for route '${r.sni}' — isolating route:`, (err as Error).message);
		return { ...r, cert: UNRESOLVABLE_CERT, mtls: undefined };
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
		// Resolve asnDatabasePath relative to the config file's directory so relative
		// paths work the same as certChainFile/privateKeyFile. The Rust load_asn_reader()
		// then calls canonicalize() on the absolute path it receives here.
		protection: l.protection
			? {
					...l.protection,
					asnDatabasePath: l.protection.asnDatabasePath
						? resolvePath(l.protection.asnDatabasePath, baseDir)
						: undefined,
				}
			: undefined,
	}));
	const routes: RouteConfig[] = spec.routes.map((r) => resolveRoute(r, baseDir));
	return { listeners, routes, workerThreads: spec.workerThreads, readBufferSize: spec.readBufferSize };
}

// Sorted listener ports identify a proxy across reloads (the route table is per-proxy,
// so each external port keeps its own SymphonyProxy — matching host-manager's model).
function portKey(listeners: { port: number }[]): string {
	return listeners
		.map((l) => l.port)
		.sort((a, b) => a - b)
		.join(',');
}

interface ActiveProxy {
	proxy: SymphonyProxy;
	listenerSig: string;
}

class ServerState {
	private readonly configPath: string;
	private readonly statusPath: string;
	private readonly baseDir: string;
	private readonly active = new Map<string, ActiveProxy>();
	private startedAt = '';
	private reloading: Promise<void> = Promise.resolve();
	private watcher: ReturnType<typeof watch> | null = null;
	// Cert/key files referenced by the current config, watched for rotation. Keyed by
	// parent directory (one fs.watch per dir, deduped) → the set of basenames we care about
	// in that dir, so an unrelated file change in the same dir is ignored.
	private readonly certWatchers = new Map<string, ReturnType<typeof watch>>();
	private certFilesByDir = new Map<string, Set<string>>();
	private debounceTimer: NodeJS.Timeout | null = null;

	constructor(configPath: string, statusPath: string) {
		this.configPath = configPath;
		this.statusPath = statusPath;
		this.baseDir = dirname(configPath);
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
				// Watch ASN DB alongside cert files so an in-place refresh triggers a
				// hot-reload without a config.json write (host-manager rotates in-place).
				if (l.protection?.asnDatabasePath) add(l.protection.asnDatabasePath);
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
				const listenerSig = JSON.stringify(
					proxyConfig.listeners.map(({ protection, ...rest }) => ({
						...rest,
						hasProtection: protection != null,
					})),
				);
				if (existing && existing.listenerSig === listenerSig) {
					// Same listeners (presence-unchanged) → hot-swap routes and protection contents.
					// All listeners here either had protection from the start (Some) or never did
					// (None, excluded by filter). none→some / some→none went through the recreate path.
					existing.proxy.updateConfig({
						routes: proxyConfig.routes,
						protection: proxyConfig.listeners
							.filter((l) => l.protection != null)
							.map((l) => ({ port: l.port, protection: l.protection! })),
					});
				} else {
					// New port-set, or listener settings changed → (re)create. SO_REUSEPORT lets the
					// new listener bind before the old one is dropped, so there is no bind gap.
					const proxy = new SymphonyProxy(proxyConfig);
					proxy.on('error', (err, ctx) =>
						logErr(`proxy [${key}] error${ctx?.listener ? ` (${ctx.listener})` : ''}:`, err)
					);
					await proxy.start();
					if (existing) await existing.proxy.stop().catch((err) => logErr(`stopping old proxy [${key}]:`, err));
					this.active.set(key, { proxy, listenerSig });
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

		this.writeStatus();
	}

	private writeStatus(): void {
		const ports = [...this.active.keys()].flatMap((k) => k.split(',').map(Number));
		const status = {
			pid: process.pid,
			version: pkg.version,
			startedAt: this.startedAt,
			reloadedAt: new Date().toISOString(),
			configPath: this.configPath,
			ports,
		};
		try {
			// Atomic write (temp + rename): the status file is rewritten on every reload, and a
			// supervisor polling it concurrently must never read a half-written document.
			const tmp = `${this.statusPath}.tmp`;
			writeFileSync(tmp, JSON.stringify(status, null, 2));
			renameSync(tmp, this.statusPath);
		} catch (err) {
			logErr(`could not write status ${this.statusPath}:`, (err as Error).message);
		}
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
		await this.reloading.catch(() => {});
		for (const [key, entry] of this.active) {
			await entry.proxy.stop().catch((err) => logErr(`stopping proxy [${key}]:`, err));
		}
		this.active.clear();
		// Only remove status.json if this process still owns it. During a version upgrade the
		// replacement starts first (SO_REUSEPORT overlap) and rewrites status.json with its own
		// pid before this incumbent is retired; an unconditional unlink here would delete the
		// successor's file and make host-manager's health check read null → respawn a duplicate.
		// Best-effort: a missing or garbage status file must not throw out of stop().
		try {
			const current = JSON.parse(readFileSync(this.statusPath, 'utf8')) as { pid?: number };
			if (current.pid === process.pid) unlinkSync(this.statusPath);
		} catch {
			// status file missing, unreadable, or not ours — leave it alone
		}
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

	const configPath = isAbsolute(args.config!) ? args.config! : join(process.cwd(), args.config!);
	const statusPath = args.status
		? isAbsolute(args.status)
			? args.status
			: join(process.cwd(), args.status)
		: join(dirname(configPath), 'status.json');

	const state = new ServerState(configPath, statusPath);
	log(`symphony-server v${pkg.version} starting (pid ${process.pid})`);
	await state.start();

	let shuttingDown = false;
	const shutdown = (sig: string) => {
		if (shuttingDown) return;
		shuttingDown = true;
		log(`received ${sig}, shutting down`);
		state
			.stop()
			.then(() => process.exit(0))
			.catch((err) => {
				logErr('error during shutdown:', err);
				process.exit(1);
			});
	};
	process.on('SIGTERM', () => shutdown('SIGTERM'));
	process.on('SIGINT', () => shutdown('SIGINT'));
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
