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

// Resolve a file-backed proxy spec into the in-memory ProxyConfig the napi layer accepts.
function toProxyConfig(spec: FileProxyConfig, baseDir: string): ProxyConfig {
	const listeners: ListenerConfig[] = spec.listeners.map((l) => ({
		...l,
		defaultCert: l.defaultCert ? resolveCert(l.defaultCert, baseDir) : undefined,
		mtls: l.mtls ? resolveMtls(l.mtls, baseDir) : undefined,
	}));
	const routes: RouteConfig[] = spec.routes.map((r) => ({
		...r,
		cert: r.cert ? resolveCert(r.cert, baseDir) : undefined,
		mtls: r.mtls ? resolveMtls(r.mtls, baseDir) : undefined,
	}));
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

	private async doReconcile(): Promise<void> {
		const config = this.readConfig();
		if (!config) return;

		const seen = new Set<string>();
		for (const spec of config.proxies) {
			const key = portKey(spec.listeners);
			seen.add(key);
			const listenerSig = JSON.stringify(spec.listeners);
			const existing = this.active.get(key);
			let proxyConfig: ProxyConfig;
			try {
				proxyConfig = toProxyConfig(spec, this.baseDir);
			} catch (err) {
				logErr(`failed to resolve certs for proxy [${key}] — skipping:`, (err as Error).message);
				continue;
			}

			if (existing && existing.listenerSig === listenerSig) {
				// Same listeners → hot-swap the route table only.
				existing.proxy.updateConfig({ routes: proxyConfig.routes });
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
		}

		// Drop proxies whose port-set is no longer in the config.
		for (const [key, entry] of this.active) {
			if (!seen.has(key)) {
				await entry.proxy.stop().catch((err) => logErr(`stopping removed proxy [${key}]:`, err));
				this.active.delete(key);
				log(`proxy on ports [${key}] removed`);
			}
		}

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
		let timer: NodeJS.Timeout | null = null;
		const base = basename(this.configPath);
		this.watcher = watch(this.baseDir, (_event, filename) => {
			if (filename && filename !== base) return;
			if (timer) clearTimeout(timer);
			timer = setTimeout(() => void this.reconcile(), 300);
		});
		// Without an 'error' listener an fs.watch error would throw as an unhandled exception.
		this.watcher.on('error', (err) => logErr('config watcher error:', err));
		log(`watching ${this.configPath} for changes`);
	}

	async stop(): Promise<void> {
		if (this.watcher) {
			this.watcher.close();
			this.watcher = null;
		}
		await this.reloading.catch(() => {});
		for (const [key, entry] of this.active) {
			await entry.proxy.stop().catch((err) => logErr(`stopping proxy [${key}]:`, err));
		}
		this.active.clear();
		try {
			unlinkSync(this.statusPath);
		} catch {
			// best effort
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
