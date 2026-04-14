import { EventEmitter } from 'node:events';
import * as path from 'node:path';
import type { SymphonyProxyWrap, JsUpstream, JsCertConfig, JsMtlsConfig, JsRouteConfig, JsListenerConfig } from './addon';
import type {
	ProxyConfig,
	HotConfig,
	ProxyMetrics,
	BlockedIpsInfo,
	ResolveRoute,
	Upstream,
	CertConfig,
	MtlsConfig,
	RouteConfig,
	ProxyEvent,
	SuspendedConnection,
} from './types';

// Load the native addon. Supports both the flat-file (dev) and npm scoped
// package (published) layouts that napi-rs produces.
function loadAddon(): { SymphonyProxyWrap: typeof SymphonyProxyWrap } {
	// __dirname is the compiled output dir (e.g. dist/ts/ or dist-test/ts/).
	// The package root (where .node files live) is two levels up.
	const pkgRoot = path.resolve(__dirname, '..', '..');
	const arch = process.arch; // 'x64' or 'arm64'
	const platform = process.platform; // 'linux' or 'darwin'

	const candidates: string[] = [
		// Dev / local build: flat .node file in package root
		path.join(pkgRoot, `symphony.${platform}-${arch}.node`),
		path.join(pkgRoot, `symphony.${platform}-${arch}-gnu.node`),
	];

	// Published scoped packages
	if (platform === 'linux') {
		candidates.push(`@symphony/linux-${arch}-gnu`, `@symphony/linux-${arch}-musl`);
	} else if (platform === 'darwin') {
		candidates.push(`@symphony/darwin-${arch}`);
	}

	for (const c of candidates) {
		try {
			return require(c);
		} catch {
			// try next
		}
	}
	throw new Error('symphony: could not load native addon. Run `npm run build:debug` first.');
}

// Convert public Upstream → JsUpstream (the flat struct the Rust side expects)
function toJsUpstream(u: Upstream): JsUpstream {
	if (u.kind === 'tcp') {
		return { kind: 'tcp', host: u.host, port: u.port };
	}
	return {
		kind: 'uds',
		path: u.path,
		ipAffinity: u.ipAffinity,
		ipAffinityTtlMs: u.ipAffinityTtlMs,
	};
}

function toJsCert(c: CertConfig): JsCertConfig {
	return {
		certChain: c.certChain,
		privateKey: c.privateKey,
	};
}

function toJsMtls(m: MtlsConfig): JsMtlsConfig {
	return {
		clientCaCert: m.clientCaCert,
		requireClientCert: m.requireClientCert,
	};
}

function toJsRoute(r: RouteConfig): JsRouteConfig {
	return {
		sni: r.sni,
		upstreams: r.upstreams.map(toJsUpstream),
		terminateTls: r.terminateTls,
		cert: r.cert ? toJsCert(r.cert) : undefined,
		mtls: r.mtls ? toJsMtls(r.mtls) : undefined,
		suspended: r.suspended,
		suspendTimeoutMs: r.suspendTimeoutMs,
	};
}

function toJsListenerConfig(l: import('./types.js').ListenerConfig): JsListenerConfig {
	return {
		host: l.host,
		port: l.port,
		defaultCert: l.defaultCert ? toJsCert(l.defaultCert) : undefined,
		mtls: l.mtls ? toJsMtls(l.mtls) : undefined,
		maxConnections: l.maxConnections,
		idleTimeoutMs: l.idleTimeoutMs,
		protection: l.protection
			? {
					rateLimit: l.protection.rateLimit
						? {
								connectionsPerSecond: l.protection.rateLimit.connectionsPerSecond,
								burst: l.protection.rateLimit.burst,
							}
						: undefined,
					maxConcurrentPerIp: l.protection.maxConcurrentPerIp,
					allowlist: l.protection.allowlist,
					blocklist: l.protection.blocklist,
					ja3Blocklist: l.protection.ja3Blocklist,
					tlsHandshakeTimeoutMs: l.protection.tlsHandshakeTimeoutMs,
					requireSni: l.protection.requireSni,
				}
			: undefined,
	};
}

export interface SymphonyProxyEvents {
	blocked: [event: { ip: string; reason: string; listener: string }];
	suspended: [conn: SuspendedConnection];
	error: [err: Error, ctx?: { listener?: string }];
	ready: [];
	close: [];
}

/**
 * High-performance TLS termination proxy with SNI-based routing.
 *
 * Events:
 *   'ready'     — emitted when all listeners are bound and accepting
 *   'close'     — emitted after stop() completes
 *   'blocked'   — { ip, reason, listener } when a connection is blocked
 *   'suspended' — { id, sni, peerIp, peerPort, listener } when a suspended route receives a connection
 *   'error'     — (err, { listener }) for internal errors
 */
export class SymphonyProxy extends EventEmitter {
	private readonly _inner: SymphonyProxyWrap;
	private _started = false;

	constructor(config: ProxyConfig) {
		super();
		const { SymphonyProxyWrap: Wrap } = loadAddon();

		const jsConfig = {
			listeners: config.listeners.map(toJsListenerConfig),
			routes: config.routes.map(toJsRoute),
			workerThreads: config.workerThreads,
			readBufferSize: config.readBufferSize,
		};

		this._inner = new Wrap(jsConfig, (err, raw) => {
			if (err) {
				this.emit('error', err);
				return;
			}
			const event = raw as ProxyEvent;
			switch (event.type) {
				case 'blocked':
					this.emit('blocked', { ip: event.ip, reason: event.reason, listener: event.listener });
					break;
				case 'suspended':
					this.emit('suspended', {
						id: event.id,
						sni: event.sni,
						peerIp: event.peerIp,
						peerPort: event.peerPort,
						listener: event.listener,
					} satisfies SuspendedConnection);
					break;
				case 'error':
					this.emit('error', new Error(event.message), { listener: event.listener });
					break;
			}
		});
	}

	async start(): Promise<void> {
		if (this._started) return;
		this._started = true;
		await this._inner.start();
		this.emit('ready');
	}

	async stop(timeoutMs = 100): Promise<void> {
		await this._inner.stop(timeoutMs);
		this._started = false;
		this.emit('close');
	}

	/**
	 * Atomically replace the route table and/or protection config.
	 * In-flight connections are unaffected.
	 */
	updateConfig(config: HotConfig): void {
		this._inner.updateConfig({
			routes: config.routes?.map(toJsRoute),
		});
	}

	metrics(): ProxyMetrics {
		const m = this._inner.metrics();
		return {
			activeConnections: m.activeConnections,
			blockedConnections: m.blockedConnections,
			pendingSuspended: m.pendingSuspended,
		};
	}

	/**
	 * Returns IPs currently rate-limited or concurrency-limited.
	 * Also returns the configured CIDR blocklist.
	 */
	blockedIps(): BlockedIpsInfo {
		return this._inner.blockedIps();
	}

	/**
	 * Resolve a suspended connection.
	 * @param id    The connection ID from the 'suspended' event
	 * @param route Provide a route to proxy, or null/undefined to reject (close TCP)
	 */
	resolveConnection(id: string, route?: ResolveRoute | null): void {
		if (!route) {
			this._inner.resolveConnection(id, null);
			return;
		}
		this._inner.resolveConnection(id, {
			upstreams: route.upstreams.map(toJsUpstream),
			terminateTls: route.terminateTls,
			cert: route.cert ? toJsCert(route.cert) : undefined,
			mtls: route.mtls ? toJsMtls(route.mtls) : undefined,
		});
	}
}
