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
import { chmodSync, existsSync, lstatSync, renameSync, unlinkSync } from 'node:fs';
import type { ProxyMetrics } from './types.js';

/** One thing to listen on. `precheck` may reject the bind before a server is created. */
interface BindTarget {
	describe: string;
	listen: (server: Server) => void;
	precheck?: () => Promise<void>;
	/** Runs once bound; throwing fails the bind (the caller closes the server and retries). */
	onBound?: () => void;
	/** Best-effort removal of anything `listen`/`onBound` left behind on a failed attempt. */
	cleanup?: () => void;
}

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
const KEEP_ALIVE_MS = 5_000;
const PROBE_TIMEOUT_MS = 1_000;
/** Hard ceiling on concurrent admin connections — a scrape endpoint needs a handful at most. */
const MAX_ADMIN_CONNECTIONS = 16;

// ── Prometheus rendering ──────────────────────────────────────────────────────

// Text exposition permits LF line endings only, then escapes `\`, `"`, and LF in label values.
function escapeLabel(value: string): string {
	return value.replace(/\r\n?/g, '\n').replace(/\\/g, '\\\\').replace(/"/g, '\\"').replace(/\n/g, '\\n');
}

function labels(pairs: Record<string, string>): string {
	const rendered = Object.entries(pairs)
		.map(([k, v]) => `${k}="${escapeLabel(v)}"`)
		.join(',');
	return rendered ? `{${rendered}}` : '';
}

/**
 * Accumulates samples grouped by metric name.
 *
 * The exposition format requires every sample of a metric name to be contiguous, under a single
 * HELP/TYPE pair. Emitting in call order would interleave them — with more than one proxy
 * configured, `symphony_routes` for the second proxy would land after the first proxy's listener
 * samples, and strict parsers reject or drop the split group. Grouping here means the callers
 * below can stay in the natural proxy → listener iteration order.
 */
class Exposition {
	private readonly groups = new Map<string, { type: 'counter' | 'gauge'; help: string; samples: string[] }>();

	sample(
		name: string,
		type: 'counter' | 'gauge',
		help: string,
		value: number,
		tags: Record<string, string> = {}
	): void {
		let group = this.groups.get(name);
		if (!group) this.groups.set(name, (group = { type, help, samples: [] }));
		group.samples.push(`${name}${labels(tags)} ${value}`);
	}

	toString(): string {
		const lines: string[] = [];
		for (const [name, { type, help, samples }] of this.groups) {
			lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} ${type}`, ...samples);
		}
		return `${lines.join('\n')}\n`;
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
			'Routes rejected at build time (cert failure, protocol/carrier validation failure, or duplicate wildcard) — dropped, or (cert failures only) serving a carried-forward last-good cert.',
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

		for (const route of metrics.routeMetrics ?? []) {
			const tags = { ...proxy, route: route.route, group: route.metricsGroup };

			out.sample(
				'symphony_route_active_connections',
				'gauge',
				'Connections currently assigned to a configured route, aggregated across proxy listeners.',
				route.activeConnections,
				tags
			);
			out.sample(
				'symphony_route_connections_total',
				'counter',
				'Connections assigned to a configured route.',
				route.connections,
				tags
			);
			out.sample(
				'symphony_route_bytes_received_total',
				'counter',
				'Bytes read from clients after route assignment (client → upstream).',
				route.bytesReceived,
				tags
			);
			out.sample(
				'symphony_route_bytes_sent_total',
				'counter',
				'Bytes written to clients after route assignment (upstream → client).',
				route.bytesSent,
				tags
			);
			for (const { reason, count } of route.errorsByReason) {
				out.sample('symphony_route_errors_total', 'counter', 'Post-route connection failures by reason.', count, {
					...tags,
					reason,
				});
			}
		}
	}

	return out.toString();
}

// ── Server ────────────────────────────────────────────────────────────────────

/**
 * Whether `socketPath` is safe to remove and rebind.
 *
 * Reclaimable means two things, and both must hold — the cost of getting this wrong is deleting
 * a *live* endpoint out from under a running process, which is the failure mode symphony's
 * status.json ownership guard exists to prevent:
 *
 *  - `ECONNREFUSED` specifically, not merely "the probe failed". A live socket with restrictive
 *    permissions (or one owned by another uid) refuses the probe with `EACCES`; treating every
 *    error as stale would unlink it. Anything that isn't a definitive "nobody is listening"
 *    leaves the path alone and the bind is retried instead.
 *  - The inode is actually a socket. Left to `EADDRINUSE` alone, a `socketPath` misconfigured
 *    onto a regular file (say, status.json) would see the connect fail and delete that file.
 */
function socketIsReclaimable(socketPath: string): Promise<boolean> {
	return new Promise((resolve) => {
		let stats;
		try {
			stats = lstatSync(socketPath);
		} catch {
			return resolve(false); // vanished under us — let the bind retry decide
		}
		if (!stats.isSocket()) return resolve(false);

		const probe = connect(socketPath);
		let settled = false;
		const done = (reclaimable: boolean) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			probe.destroy();
			resolve(reclaimable);
		};
		// A frozen owner or a full accept backlog can leave the connect hanging, which would
		// stall the reconcile that called us. Treat a hang as "not reclaimable" — something is
		// there, and refusing to touch it is the safe reading.
		const timer = setTimeout(() => done(false), PROBE_TIMEOUT_MS);
		timer.unref();
		probe.once('connect', () => done(false));
		probe.once('error', (err: NodeJS.ErrnoException) => done(err.code === 'ECONNREFUSED'));
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
	// update(), stop(), and the retry timer all mutate the same listeners, and each of them
	// awaits. Run them through one chain so a retry that is mid-bind can't publish its server
	// after a later update() or stop() has already finished tearing things down.
	private queue: Promise<void> = Promise.resolve();

	constructor(
		snapshot: () => MetricsSnapshot,
		log: (msg: string, ...rest: unknown[]) => void,
		logErr: (msg: string, ...rest: unknown[]) => void
	) {
		this.snapshot = snapshot;
		this.log = log;
		this.logErr = logErr;
	}

	/** Serialize a mutation of the listener set; failures never break the chain. */
	private enqueue(operation: () => Promise<void>): Promise<void> {
		this.queue = this.queue.then(operation, operation);
		return this.queue;
	}

	update(config: AdminConfig | undefined): Promise<void> {
		return this.enqueue(async () => {
			if (this.stopped) return;
			const signature = JSON.stringify(config ?? null);
			if (signature === this.signature) return;
			this.signature = signature;
			this.config = config ?? null;
			// Drop a pending retry from the previous config — otherwise it fires seconds later and
			// tears down the listeners this call is about to bind.
			this.clearRetry();
			await this.closeServers();
			if (config && (config.socketPath || config.port !== undefined)) await this.bind();
		});
	}

	stop(): Promise<void> {
		// Set before queueing, so an operation already waiting its turn bails instead of binding.
		this.stopped = true;
		this.clearRetry();
		return this.enqueue(() => this.closeServers());
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
			// Queued like everything else, so a retry can't interleave with an update or a stop.
			void this.enqueue(() => this.bind());
		}, RETRY_MS);
		this.retryTimer.unref();
	}

	private async bind(): Promise<void> {
		const config = this.config;
		if (this.stopped || !config) return;
		await this.closeServers();

		const targets: BindTarget[] = [];
		if (config.socketPath) targets.push(this.socketTarget(config.socketPath, config.socketMode ?? 0o660));
		if (config.port !== undefined) {
			const host = config.host ?? '127.0.0.1';
			targets.push({ describe: `${host}:${config.port}`, listen: (server) => server.listen(config.port, host) });
		}

		for (const target of targets) {
			try {
				const server = await this.listenOne(target);
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

	/**
	 * Bind the Unix socket by listening on a pid-unique temporary path and `rename`-ing it onto
	 * the real one.
	 *
	 * The obvious shape — probe, `unlink`, `listen` — has a window between the probe and the
	 * unlink. Two processes can both find the path stale, and the second one's unlink then
	 * deletes the socket the first has already bound and is serving. `rename` is atomic and
	 * replaces the target in one step, so the path always names a socket somebody is listening
	 * on. The precheck stays, because rename would otherwise happily clobber a *live* incumbent
	 * during an upgrade overlap — there we want to lose and retry, not steal the endpoint.
	 *
	 * Nothing unlinks the published path, including on a clean shutdown. Any check-then-unlink
	 * can delete a *successor's* socket in the window between the two syscalls, and that loss is
	 * not self-repairing: `update()` returns early on an unchanged signature, so the successor
	 * would keep serving an unreachable socket until its config changed or it restarted. Leaving
	 * a stale pathname behind costs one inode in a 0o700 directory, and the next binder replaces
	 * it atomically after proving it stale. Cheap litter beats a silently dead endpoint.
	 */
	private socketTarget(path: string, mode: number): BindTarget {
		const tempPath = `${path}.${process.pid}`;
		return {
			describe: path,
			precheck: async () => {
				if (existsSync(path) && !(await socketIsReclaimable(path))) {
					throw new Error(`${path} is in use by another process`);
				}
			},
			listen: (server) => server.listen(tempPath),
			onBound: () => {
				chmodSync(tempPath, mode);
				renameSync(tempPath, path);
			},
			cleanup: () => {
				try {
					unlinkSync(tempPath);
				} catch {
					// never created, or already renamed into place
				}
			},
		};
	}

	private async listenOne(target: BindTarget): Promise<Server> {
		await target.precheck?.();

		const server = createServer((req, res) => this.handle(req, res));
		// Scrapes are short and infrequent, so reap idle connections quickly. Note this is a
		// timeout, not a switch: setting it to 0 would disable the reaping, letting a client park
		// arbitrarily many idle connections against the same process-wide fd budget the proxy
		// listeners draw from. maxConnections caps that regardless of client behaviour.
		server.keepAliveTimeout = KEEP_ALIVE_MS;
		server.maxConnections = MAX_ADMIN_CONNECTIONS;

		try {
			return await new Promise<Server>((resolve, reject) => {
				const onError = (err: NodeJS.ErrnoException) => {
					server.removeListener('listening', onListening);
					reject(err);
				};
				const onListening = () => {
					server.removeListener('error', onError);
					try {
						target.onBound?.();
					} catch (err) {
						// The socket is bound but not reachable at its published path — useless, and
						// it would leak an fd and a temp inode. Fail so the retry starts clean.
						server.close();
						reject(err);
						return;
					}
					// Post-bind errors must not crash the process.
					server.on('error', (err) => this.logErr(`admin endpoint error (${target.describe}):`, err));
					resolve(server);
				};
				server.once('error', onError);
				server.once('listening', onListening);
				target.listen(server);
			});
		} catch (err) {
			target.cleanup?.();
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
