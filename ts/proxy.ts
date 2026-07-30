import { EventEmitter } from 'node:events';
import * as path from 'node:path';
import type {
	SymphonyProxyWrap,
	JsUpstream,
	JsCertConfig,
	JsMtlsConfig,
	JsRouteConfig,
	JsListenerConfig,
} from './addon';
import type {
	ProxyConfig,
	HotConfig,
	ProxyMetrics,
	BlockedIpsInfo,
	ResolveRoute,
	Upstream,
	CertConfig,
	MtlsConfig,
	ProtectionConfig,
	RouteConfig,
	ProxyEvent,
	SuspendedConnection,
} from './types';

// Load the native addon. Supports both the flat-file (dev) and npm scoped
// package (published) layouts that napi-rs produces.
function loadAddon(): { SymphonyProxyWrap: typeof SymphonyProxyWrap } {
	// __dirname varies by build layout:
	//   dist/proxy.js        → one level below package root (outDir: "dist", rootDir: "ts")
	//   dist-test/ts/proxy.js → two levels below package root (outDir: "dist-test", rootDir: ".")
	// Try both so the same source works for production and test builds.
	const arch = process.arch; // 'x64' or 'arm64'
	const platform = process.platform; // 'linux' or 'darwin'

	const candidates: string[] = [
		// Dev / local build: flat .node file in package root (try both possible depths)
		path.join(__dirname, '..', `symphony.${platform}-${arch}.node`),
		path.join(__dirname, '..', `symphony.${platform}-${arch}-gnu.node`),
		path.join(__dirname, '..', '..', `symphony.${platform}-${arch}.node`),
		path.join(__dirname, '..', '..', `symphony.${platform}-${arch}-gnu.node`),
	];

	// Published scoped packages
	if (platform === 'linux') {
		candidates.push(`@harperfast/symphony-linux-${arch}-gnu`, `@harperfast/symphony-linux-${arch}-musl`);
	} else if (platform === 'darwin') {
		candidates.push(`@harperfast/symphony-darwin-${arch}`);
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
		// Forward `protocol` even though TcpUpstream doesn't declare it, so an untyped
		// config (e.g. symphony-server JSON) setting it gets the napi-layer rejection
		// instead of a silent strip.
		return { kind: 'tcp', host: u.host, port: u.port, protocol: (u as { protocol?: string }).protocol };
	}
	return {
		kind: 'uds',
		path: u.path,
		ipAffinity: u.ipAffinity,
		ipAffinityTtlMs: u.ipAffinityTtlMs,
		pid: u.pid,
		tid: u.tid,
		protocol: u.protocol,
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
		maxConnectionsPerSecond: r.maxConnectionsPerSecond,
		burst: r.burst,
		sourceAddressHeader: r.sourceAddressHeader,
		forwardFingerprint: r.forwardFingerprint,
		http2: r.http2,
		protocol: r.protocol,
	};
}

function toJsProtectionConfig(p: ProtectionConfig) {
	return {
		rateLimit: p.rateLimit
			? { connectionsPerSecond: p.rateLimit.connectionsPerSecond, burst: p.rateLimit.burst }
			: undefined,
		sustained: p.sustained
			? { connectionsPerMinute: p.sustained.connectionsPerMinute, burst: p.sustained.burst }
			: undefined,
		penaltyBox: p.penaltyBox ? { durationMs: p.penaltyBox.durationMs } : undefined,
		maxConcurrentPerIp: p.maxConcurrentPerIp,
		allowlist: p.allowlist,
		blocklist: p.blocklist,
		ja3Blocklist: p.ja3Blocklist,
		ja4Blocklist: p.ja4Blocklist,
		tlsHandshakeTimeoutMs: p.tlsHandshakeTimeoutMs,
		requireSni: p.requireSni,
	};
}

function toJsListenerConfig(l: import('./types.js').ListenerConfig): JsListenerConfig {
	return {
		host: l.host,
		port: l.port,
		mode: l.mode,
		defaultCert: l.defaultCert ? toJsCert(l.defaultCert) : undefined,
		mtls: l.mtls ? toJsMtls(l.mtls) : undefined,
		maxConnections: l.maxConnections,
		idleTimeoutMs: l.idleTimeoutMs,
		protection: l.protection ? toJsProtectionConfig(l.protection) : undefined,
	};
}

export interface SymphonyProxyEvents {
	blocked: [event: { ip: string; reason: string; listener: string; ja3: string; ja4: string }];
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
			clientReadBufferSize: config.clientReadBufferSize,
			upstreamReadBufferSize: config.upstreamReadBufferSize,
		};

		this._inner = new Wrap(jsConfig, (err, raw) => {
			if (err) {
				this.emit('error', err);
				return;
			}
			// A listener can throw synchronously — most notably a 'suspended' handler that calls
			// resolveConnection() with a route the new protocol/carrier validation rejects, which
			// used to be a silent no-op and is now a thrown Error. EventEmitter.emit() propagates a
			// listener's throw straight back to its caller, which here is this napi threadsafe
			// function callback: left unguarded, that throw escapes into native code as an uncaught
			// exception and takes the whole process down. Route it to 'error' instead, matching how
			// every other proxy-level error already reaches user code.
			try {
				const event = raw as ProxyEvent;
				switch (event.type) {
					case 'blocked':
						this.emit('blocked', {
							ip: event.ip,
							reason: event.reason,
							listener: event.listener,
							ja3: event.ja3,
							ja4: event.ja4,
						});
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
			} catch (listenerErr) {
				// If nothing is listening for 'error', emit('error', ...) itself throws (Node's
				// EventEmitter contract — every consumer of this class must attach one), which
				// would otherwise recurse right back into this catch with no way out, escaping as
				// an unhandled double-throw that also replaces the original stack with a generic
				// one. Re-emit only when a listener actually exists; otherwise propagate the
				// original error as-is rather than trying (and failing) to route it through 'error'.
				if (this.listenerCount('error') > 0) {
					this.emit('error', listenerErr instanceof Error ? listenerErr : new Error(String(listenerErr)));
				} else {
					throw listenerErr;
				}
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
	 * Atomically update routes and/or per-listener protection config.
	 * In-flight connections are unaffected.
	 * Throws if any protection entry references a port that has no protection or matches no listener.
	 */
	updateConfig(config: HotConfig): void {
		this._inner.updateConfig({
			routes: config.routes?.map(toJsRoute),
			protection: config.protection?.map((p) => ({
				port: p.port,
				protection: toJsProtectionConfig(p.protection),
			})),
		});
	}

	metrics(): ProxyMetrics {
		const m = this._inner.metrics();
		return {
			activeConnections: m.activeConnections,
			blockedConnections: m.blockedConnections,
			pendingSuspended: m.pendingSuspended,
			suspendedResolved: m.suspendedResolved,
			suspendedUnresolved: m.suspendedUnresolved,
			routes: m.routes,
			failingRoutes: m.failingRoutes,
			listeners: m.listeners.map((l) => ({
				address: l.address,
				mode: l.mode as 'tls' | 'http',
				activeConnections: l.activeConnections,
				accepted: l.accepted,
				blocked: l.blocked,
				errors: l.errors,
				bytesReceived: l.bytesReceived,
				bytesSent: l.bytesSent,
				blockedByReason: l.blockedByReason.map((c) => ({ reason: c.reason, count: c.count })),
				errorsByReason: l.errorsByReason.map((c) => ({ reason: c.reason, count: c.count })),
			})),
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
			upstream: toJsUpstream(route.upstream),
			terminateTls: route.terminateTls,
			cert: route.cert ? toJsCert(route.cert) : undefined,
			mtls: route.mtls ? toJsMtls(route.mtls) : undefined,
			sourceAddressHeader: route.sourceAddressHeader,
			forwardFingerprint: route.forwardFingerprint,
			http2: route.http2,
			protocol: route.protocol,
		});
	}
}
