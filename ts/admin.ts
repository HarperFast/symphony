//! Read-only admin/metrics endpoint for the standalone `symphony-server`.
//!
//! Consumers that run symphony out-of-process have no access to the napi `metrics()` call, so
//! the server exposes the same numbers over HTTP:
//!
//!   GET /metrics       Prometheus text exposition (v0.0.4)
//!   GET /metrics.json  the same snapshot as JSON
//!   GET /health        liveness (`{ ok, pid, version, ports }`)
//!
//! It binds a Unix socket, a loopback TCP port, or both. Everything here is best-effort: a
//! bind failure or a handler throw must never affect proxying, so failures are logged and
//! retried rather than propagated.

import { createServer, type Server, type IncomingMessage, type ServerResponse } from 'node:http';
import { connect } from 'node:net';
import { chmodSync, unlinkSync } from 'node:fs';
import type { ProxyMetrics } from './types.js';

export interface AdminConfig {
	/** Unix socket path to listen on. Relative paths resolve against the config file's directory. */
	socketPath?: string;
	/** Permissions applied to `socketPath` after bind. Default 0o660. */
	socketMode?: number;
	/** TCP port to listen on. */
	port?: number;
	/** Interface for `port`. Default 127.0.0.1 — do not expose metrics off-box without a reason. */
	host?: string;
}

/** One running proxy's identity and current counters. */
export interface ProxySnapshot {
	/** Sorted listener ports for this proxy, as configured ("80,443"). */
	ports: string;
	metrics: ProxyMetrics;
}

export interface MetricsSnapshot {
	pid: number;
	version: string;
	startedAt: string;
	reloadedAt: string;
	proxies: ProxySnapshot[];
}

const RETRY_MS = 5_000;

// ── Prometheus rendering ──────────────────────────────────────────────────────

// Only `\`, `"` and newline are special in a label value (exposition format v0.0.4).
function escapeLabel(value: string): string {
	return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

function labels(pairs: Record<string, string>): string {
	const rendered = Object.entries(pairs)
		.map(([k, v]) => `${k}="${escapeLabel(v)}"`)
		.join(',');
	return rendered ? `{${rendered}}` : '';
}

class Exposition {
	private readonly lines: string[] = [];
	private declared = new Set<string>();

	/** Emit HELP/TYPE once per metric name, then a sample. */
	sample(
		name: string,
		type: 'counter' | 'gauge',
		help: string,
		value: number,
		tags: Record<string, string> = {}
	): void {
		if (!this.declared.has(name)) {
			this.declared.add(name);
			this.lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`);
		}
		this.lines.push(`${name}${labels(tags)} ${value}`);
	}

	toString(): string {
		return `${this.lines.join('\n')}\n`;
	}
}

/**
 * Render a snapshot as Prometheus text.
 *
 * Blocked and error counts are only ever emitted with their `reason` label — the per-reason
 * series sum to the unlabeled total by construction, so a separate total would be a second
 * representation of the same number. Use `sum without(reason)` for the total. Likewise the
 * proxy-level active-connection gauge is `sum without(listener)` of the per-listener one.
 */
export function renderPrometheus(snapshot: MetricsSnapshot): string {
	const out = new Exposition();

	out.sample('symphony_build_info', 'gauge', 'Always 1; the version is carried in the label.', 1, {
		version: snapshot.version,
	});
	out.sample(
		'symphony_start_time_seconds',
		'gauge',
		'Unix time the server process started.',
		Date.parse(snapshot.startedAt) / 1000
	);
	out.sample(
		'symphony_config_reload_time_seconds',
		'gauge',
		'Unix time of the last successful config reconcile.',
		Date.parse(snapshot.reloadedAt) / 1000
	);

	for (const { ports, metrics } of snapshot.proxies) {
		const proxy = { proxy: ports };

		out.sample(
			'symphony_routes',
			'gauge',
			'Routes in the live table, including the default route.',
			metrics.routes,
			proxy
		);
		out.sample(
			'symphony_routes_failing',
			'gauge',
			'Routes whose cert failed to build — dropped, or serving a carried-forward last-good cert.',
			metrics.failingRoutes,
			proxy
		);
		out.sample(
			'symphony_suspended_pending',
			'gauge',
			'Connections held awaiting resolveConnection().',
			metrics.pendingSuspended,
			proxy
		);
		out.sample(
			'symphony_suspended_total',
			'counter',
			'Suspended connections by how they ended.',
			metrics.suspendedResolved,
			{
				...proxy,
				outcome: 'resolved',
			}
		);
		out.sample(
			'symphony_suspended_total',
			'counter',
			'Suspended connections by how they ended.',
			metrics.suspendedUnresolved,
			{
				...proxy,
				outcome: 'unresolved',
			}
		);

		for (const l of metrics.listeners) {
			const tags = { ...proxy, listener: l.address, mode: l.mode };

			out.sample(
				'symphony_listener_active_connections',
				'gauge',
				'Connections currently being proxied.',
				l.activeConnections,
				tags
			);
			out.sample('symphony_listener_accepted_total', 'counter', 'Connections accepted for proxying.', l.accepted, tags);
			out.sample(
				'symphony_listener_bytes_received_total',
				'counter',
				'Bytes read from clients (client → upstream).',
				l.bytesReceived,
				tags
			);
			out.sample(
				'symphony_listener_bytes_sent_total',
				'counter',
				'Bytes written to clients (upstream → client).',
				l.bytesSent,
				tags
			);
			for (const { reason, count } of l.blockedByReason) {
				out.sample(
					'symphony_listener_blocked_total',
					'counter',
					'Connections rejected before proxying, by reason.',
					count,
					{
						...tags,
						reason,
					}
				);
			}
			for (const { reason, count } of l.errorsByReason) {
				out.sample('symphony_listener_errors_total', 'counter', 'Connections that failed, by reason.', count, {
					...tags,
					reason,
				});
			}
		}
	}

	return out.toString();
}

// ── Server ────────────────────────────────────────────────────────────────────

/** True if something is actively listening on `socketPath` (as opposed to a stale socket file). */
function socketIsLive(socketPath: string): Promise<boolean> {
	return new Promise((resolve) => {
		const probe = connect(socketPath);
		const done = (live: boolean) => {
			probe.destroy();
			resolve(live);
		};
		probe.once('connect', () => done(true));
		probe.once('error', () => done(false));
	});
}

/**
 * Owns the admin listeners for the lifetime of the process. `update()` is idempotent: it is
 * called on every reconcile and only rebuilds when the admin config actually changed.
 */
export class AdminServer {
	private readonly snapshot: () => MetricsSnapshot;
	private readonly log: (msg: string, ...rest: unknown[]) => void;
	private readonly logErr: (msg: string, ...rest: unknown[]) => void;
	private servers: Server[] = [];
	private signature = '';
	private config: AdminConfig | null = null;
	private retryTimer: NodeJS.Timeout | null = null;
	private stopped = false;

	constructor(
		snapshot: () => MetricsSnapshot,
		log: (msg: string, ...rest: unknown[]) => void,
		logErr: (msg: string, ...rest: unknown[]) => void
	) {
		this.snapshot = snapshot;
		this.log = log;
		this.logErr = logErr;
	}

	async update(config: AdminConfig | undefined): Promise<void> {
		if (this.stopped) return;
		const signature = JSON.stringify(config ?? null);
		if (signature === this.signature) return;
		this.signature = signature;
		this.config = config ?? null;
		await this.closeServers();
		if (config && (config.socketPath || config.port !== undefined)) await this.bind();
	}

	async stop(): Promise<void> {
		this.stopped = true;
		this.clearRetry();
		await this.closeServers();
	}

	private clearRetry(): void {
		if (this.retryTimer) {
			clearTimeout(this.retryTimer);
			this.retryTimer = null;
		}
	}

	// A failed bind is retried rather than thrown: during a version upgrade the incumbent still
	// holds the admin socket/port (the proxy listeners overlap via SO_REUSEPORT, but a Node HTTP
	// server has no such luxury), so the successor binds a few seconds later once it exits.
	private scheduleRetry(): void {
		if (this.stopped || this.retryTimer) return;
		this.retryTimer = setTimeout(() => {
			this.retryTimer = null;
			void this.bind();
		}, RETRY_MS);
		this.retryTimer.unref();
	}

	private async bind(): Promise<void> {
		const config = this.config;
		if (this.stopped || !config) return;
		await this.closeServers();

		const targets: Array<{ describe: string; listen: (server: Server) => void; onBound?: () => void }> = [];
		if (config.socketPath) {
			const path = config.socketPath;
			targets.push({
				describe: path,
				listen: (server) => server.listen(path),
				onBound: () => chmodSync(path, config.socketMode ?? 0o660),
			});
		}
		if (config.port !== undefined) {
			const host = config.host ?? '127.0.0.1';
			targets.push({ describe: `${host}:${config.port}`, listen: (server) => server.listen(config.port, host) });
		}

		for (const target of targets) {
			try {
				const server = await this.listenOne(target, config);
				this.servers.push(server);
				this.log(`admin endpoint listening on ${target.describe}`);
			} catch (err) {
				this.logErr(`could not bind admin endpoint on ${target.describe} (retrying):`, (err as Error).message);
				// Drop any sibling that did bind so a retry starts from a clean slate and can't
				// double-bind the one that succeeded.
				await this.closeServers();
				this.scheduleRetry();
				return;
			}
		}
	}

	private async listenOne(
		target: { describe: string; listen: (server: Server) => void; onBound?: () => void },
		config: AdminConfig
	): Promise<Server> {
		const server = createServer((req, res) => this.handle(req, res));
		// Metrics scrapes are short; don't hold sockets open between them.
		server.keepAliveTimeout = 0;

		const attempt = (): Promise<Server> =>
			new Promise<Server>((resolve, reject) => {
				const onError = (err: NodeJS.ErrnoException) => {
					server.removeListener('listening', onListening);
					reject(err);
				};
				const onListening = () => {
					server.removeListener('error', onError);
					try {
						target.onBound?.();
					} catch (err) {
						this.logErr(`could not set permissions on ${target.describe}:`, (err as Error).message);
					}
					// Post-bind errors must not crash the process.
					server.on('error', (err) => this.logErr(`admin endpoint error (${target.describe}):`, err));
					resolve(server);
				};
				server.once('error', onError);
				server.once('listening', onListening);
				target.listen(server);
			});

		try {
			return await attempt();
		} catch (err) {
			// A Unix socket left behind by a process that died without cleaning up blocks the
			// bind forever. Only remove it once a connect probe proves nobody is listening —
			// unlinking a live socket would silently steal the endpoint from a running process.
			const code = (err as NodeJS.ErrnoException).code;
			if (code === 'EADDRINUSE' && config.socketPath && target.describe === config.socketPath) {
				if (await socketIsLive(config.socketPath)) throw err;
				this.log(`removing stale admin socket ${config.socketPath}`);
				unlinkSync(config.socketPath);
				return attempt();
			}
			throw err;
		}
	}

	private handle(req: IncomingMessage, res: ServerResponse): void {
		// Strip any query string; the endpoints take no parameters.
		const path = (req.url ?? '/').split('?')[0];
		if (req.method !== 'GET' && req.method !== 'HEAD') {
			res.writeHead(405, { allow: 'GET, HEAD' }).end();
			return;
		}

		try {
			const snapshot = this.snapshot();
			if (path === '/metrics') {
				const body = renderPrometheus(snapshot);
				res.writeHead(200, { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' }).end(body);
			} else if (path === '/metrics.json') {
				res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(snapshot));
			} else if (path === '/health') {
				const ports = snapshot.proxies.flatMap((p) => p.ports.split(',').map(Number));
				res
					.writeHead(200, { 'content-type': 'application/json' })
					.end(JSON.stringify({ ok: true, pid: snapshot.pid, version: snapshot.version, ports }));
			} else {
				res.writeHead(404, { 'content-type': 'text/plain' }).end('not found\n');
			}
		} catch (err) {
			this.logErr('admin request failed:', (err as Error).message);
			res.writeHead(500, { 'content-type': 'text/plain' }).end('internal error\n');
		}
	}

	private async closeServers(): Promise<void> {
		const servers = this.servers;
		this.servers = [];
		await Promise.all(
			servers.map(
				(server) =>
					new Promise<void>((resolve) => {
						server.close(() => resolve());
						// close() waits for in-flight requests; a scrape holding the socket must not
						// stall shutdown.
						server.closeAllConnections();
					})
			)
		);
	}
}
