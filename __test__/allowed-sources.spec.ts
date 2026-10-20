/**
 * Per-route `allowedSources`: only peers inside a route's CIDRs reach its upstream.
 *
 * Every client here connects from 127.0.0.1, so a refusal is provoked with a list that excludes
 * it (`DENY_LOCAL`). The one case that needs two sources on a single route binds 127.0.0.2, which
 * Linux routes to loopback but macOS does not without an alias, and skips where it is missing.
 */

import assert from 'node:assert/strict';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { after, before, describe, it, type TestContext } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import type { RouteConfig, SuspendedConnection } from '../ts/types.js';
import { clientHello, generateSelfSignedCert, getFreePort, sleep } from './util.js';

const DENY_LOCAL = ['10.0.0.0/8', '2001:db8::/32'];
const SECOND_SOURCE = '127.0.0.2';

interface CountingUpstream {
	port: number;
	accepted(): number;
	close(): Promise<void>;
}

function startCountingUpstream(): Promise<CountingUpstream> {
	return new Promise((resolve, reject) => {
		let accepted = 0;
		const server = net.createServer((socket) => {
			accepted++;
			socket.on('error', () => {});
			socket.pipe(socket);
		});
		server.listen(0, '127.0.0.1', () => {
			resolve({
				port: (server.address() as net.AddressInfo).port,
				accepted: () => accepted,
				close: () => new Promise((res) => server.close(() => res())),
			});
		});
		server.on('error', reject);
	});
}

/**
 * Bytes echoed back through a passthrough route for a synthetic ClientHello; 0 when symphony
 * refuses the connection. Rejects if the client never connects, so a setup failure (an
 * unassignable source address, a listener not yet bound) can't pass for a refusal.
 */
function passthroughProbe(opts: { port: number; host?: string; localAddress?: string; sni: string }): Promise<number> {
	return new Promise((resolve, reject) => {
		const hello = clientHello(opts.sni);
		let echoed = 0;
		let connected = false;
		const socket = net.createConnection(
			{ port: opts.port, host: opts.host ?? '127.0.0.1', localAddress: opts.localAddress },
			() => {
				connected = true;
				socket.write(hello);
			}
		);
		const timer = setTimeout(() => {
			socket.destroy();
			reject(new Error('passthroughProbe timeout'));
		}, 5000);
		socket.on('data', (chunk: Buffer) => {
			echoed += chunk.length;
			if (echoed >= hello.length) socket.end();
		});
		socket.on('error', (err) => {
			if (!connected) {
				clearTimeout(timer);
				reject(err);
			}
		});
		socket.on('close', () => {
			clearTimeout(timer);
			if (connected) resolve(echoed);
		});
	});
}

function passthroughRoute(sni: string, upstreamPort: number, extra: Partial<RouteConfig> = {}): RouteConfig {
	return {
		sni,
		upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: upstreamPort }],
		terminateTls: false,
		...extra,
	};
}

function routeBlocked(proxy: SymphonyProxy, route: string): number {
	const metrics = proxy.metrics().routeMetrics.find((r) => r.route === route);
	return metrics?.blockedByReason.find((r) => r.reason === 'source_not_allowed')?.count ?? 0;
}

function listenerBlocked(proxy: SymphonyProxy): number {
	return proxy.metrics().listeners[0].blockedByReason.find((r) => r.reason === 'source_not_allowed')?.count ?? 0;
}

async function canBind(host: string): Promise<boolean> {
	return new Promise((resolve) => {
		const server = net.createServer();
		server.once('error', () => resolve(false));
		server.listen(0, host, () => server.close(() => resolve(true)));
	});
}

describe('allowedSources – passthrough routes', () => {
	let upstream: CountingUpstream;
	let proxyPort: number;
	let proxy: SymphonyProxy;

	before(async () => {
		upstream = await startCountingUpstream();
		proxyPort = await getFreePort();
		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				passthroughRoute('allowed.test', upstream.port, { allowedSources: ['127.0.0.1'] }),
				passthroughRoute('cidr.test', upstream.port, { allowedSources: ['10.0.0.0/8', '127.0.0.0/30'] }),
				passthroughRoute('denied.test', upstream.port, { allowedSources: DENY_LOCAL }),
				passthroughRoute('open.test', upstream.port, { allowedSources: [] }),
			],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await upstream.close();
	});

	it('admits a peer matching a bare-IP entry', async () => {
		const before = upstream.accepted();
		assert.equal(await passthroughProbe({ port: proxyPort, sni: 'allowed.test' }), clientHello('allowed.test').length);
		assert.equal(upstream.accepted(), before + 1);
	});

	it('admits a peer matching any CIDR in the list', async () => {
		assert.ok((await passthroughProbe({ port: proxyPort, sni: 'cidr.test' })) > 0);
	});

	it('refuses a peer outside the list without opening the upstream', async () => {
		const before = upstream.accepted();
		assert.equal(await passthroughProbe({ port: proxyPort, sni: 'denied.test' }), 0);
		await sleep(50);
		assert.equal(upstream.accepted(), before, 'the upstream must never see a refused peer');
		assert.equal(routeBlocked(proxy, 'denied.test'), 1);
		assert.equal(listenerBlocked(proxy), 1);
		const route = proxy.metrics().routeMetrics.find((r) => r.route === 'denied.test')!;
		assert.equal(route.blocked, 1);
		assert.equal(route.errors, 0, 'a refusal is a block, not an error');
		assert.equal(proxy.metrics().listeners[0].blocked, 1);
	});

	it('treats an empty list as unrestricted', async () => {
		assert.ok((await passthroughProbe({ port: proxyPort, sni: 'open.test' })) > 0);
		const route = proxy.metrics().routeMetrics.find((r) => r.route === 'open.test')!;
		assert.deepEqual(route.blockedByReason, [], 'zero-valued route block reasons are omitted');
	});
});

describe('allowedSources – terminated TLS', () => {
	const cert = generateSelfSignedCert('tenant.test');
	let upstream: CountingUpstream;
	let proxyPort: number;
	let proxy: SymphonyProxy;

	before(async () => {
		upstream = await startCountingUpstream();
		proxyPort = await getFreePort();
		const route = (sni: string, allowedSources: string[]): RouteConfig => ({
			sni,
			upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: upstream.port }],
			terminateTls: true,
			cert: { certChain: cert.cert, privateKey: cert.key },
			allowedSources,
		});
		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [route('tenant.test', ['127.0.0.1']), route('closed.test', DENY_LOCAL)],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await upstream.close();
	});

	function handshake(servername: string): Promise<boolean> {
		return new Promise((resolve, reject) => {
			const socket = tls.connect({ port: proxyPort, host: '127.0.0.1', servername, rejectUnauthorized: false });
			socket.once('secureConnect', () => {
				socket.end();
				resolve(true);
			});
			socket.once('error', () => resolve(false));
			socket.once('close', () => resolve(false));
			setTimeout(() => {
				socket.destroy();
				reject(new Error('handshake timeout'));
			}, 5000).unref();
		});
	}

	it('refuses before the TLS handshake and the upstream connect', async () => {
		assert.equal(await handshake('closed.test'), false, 'a refused peer must never complete a handshake');
		await sleep(50);
		assert.equal(upstream.accepted(), 0);
		assert.equal(routeBlocked(proxy, 'closed.test'), 1);
		const route = proxy.metrics().routeMetrics.find((r) => r.route === 'closed.test')!;
		assert.deepEqual(route.errorsByReason, [], 'no tls_handshake error: the handshake never started');
	});

	it('completes the handshake for a listed peer', async () => {
		assert.equal(await handshake('tenant.test'), true);
	});
});

describe('allowedSources – IPv6 and IPv4-mapped peers', () => {
	let upstream: CountingUpstream;

	before(async () => {
		upstream = await startCountingUpstream();
	});

	after(async () => {
		await upstream.close();
	});

	async function withProxy(host: string, routes: RouteConfig[], body: (port: number) => Promise<void>, t: TestContext) {
		if (!(await canBind(host))) {
			t.skip(`cannot bind ${host}`);
			return;
		}
		const port = await getFreePort();
		// The listener host is joined to the port as `host:port`, so an IPv6 host needs brackets.
		const proxy = new SymphonyProxy({ listeners: [{ host: `[${host}]`, port }], routes });
		await proxy.start();
		await sleep(50);
		try {
			await body(port);
		} finally {
			await proxy.stop();
		}
	}

	it('matches an IPv6 peer against IPv6 CIDRs', async (t) => {
		await withProxy(
			'::1',
			[
				passthroughRoute('v6.test', upstream.port, { allowedSources: ['::1/128'] }),
				passthroughRoute('v6-denied.test', upstream.port, { allowedSources: ['2001:db8::/32', '127.0.0.1'] }),
			],
			async (port) => {
				assert.ok((await passthroughProbe({ port, host: '::1', sni: 'v6.test' })) > 0);
				const before = upstream.accepted();
				assert.equal(await passthroughProbe({ port, host: '::1', sni: 'v6-denied.test' }), 0);
				assert.equal(upstream.accepted(), before);
			},
			t
		);
	});

	it('matches an IPv4 client on a dual-stack listener against IPv4 CIDRs', async (t) => {
		await withProxy(
			'::',
			[
				passthroughRoute('mapped.test', upstream.port, { allowedSources: ['127.0.0.0/8'] }),
				passthroughRoute('mapped-cidr.test', upstream.port, { allowedSources: ['::ffff:127.0.0.1/128'] }),
				passthroughRoute('mapped-denied.test', upstream.port, { allowedSources: ['10.0.0.0/8'] }),
			],
			async (port) => {
				// Reaching a `::` listener over IPv4 needs a dual-stack socket (Linux's default).
				const echoed = await passthroughProbe({ port, host: '127.0.0.1', sni: 'mapped.test' }).catch((err) => {
					if (err.code === 'ECONNREFUSED') return null;
					throw err;
				});
				if (echoed === null) {
					t.skip('dual-stack listener not reachable over IPv4');
					return;
				}
				assert.ok(echoed > 0);
				assert.ok((await passthroughProbe({ port, host: '127.0.0.1', sni: 'mapped-cidr.test' })) > 0);
				assert.equal(await passthroughProbe({ port, host: '127.0.0.1', sni: 'mapped-denied.test' }), 0);
			},
			t
		);
	});
});

describe('allowedSources – route rate limiter', () => {
	let upstream: CountingUpstream;
	let proxyPort: number;
	let proxy: SymphonyProxy;

	before(async () => {
		upstream = await startCountingUpstream();
		proxyPort = await getFreePort();
		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				passthroughRoute('limited.test', upstream.port, {
					allowedSources: ['127.0.0.1'],
					maxConnectionsPerSecond: 0.001,
					burst: 1,
				}),
			],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await upstream.close();
	});

	it('spends no route tokens on refused peers', async (t) => {
		if (!(await canBind(SECOND_SOURCE))) {
			t.skip(`${SECOND_SOURCE} is not assignable on this host`);
			return;
		}
		for (let i = 0; i < 3; i++) {
			assert.equal(await passthroughProbe({ port: proxyPort, sni: 'limited.test', localAddress: SECOND_SOURCE }), 0);
		}
		assert.ok(
			(await passthroughProbe({ port: proxyPort, sni: 'limited.test' })) > 0,
			'the single token must still be available to the listed peer'
		);
		assert.equal(routeBlocked(proxy, 'limited.test'), 3);
	});
});

describe('allowedSources – hot reload', () => {
	let upstream: CountingUpstream;
	let proxyPort: number;
	let proxy: SymphonyProxy;
	const routes = (allowedSources?: string[]) => [passthroughRoute('reload.test', upstream.port, { allowedSources })];
	const admitted = async () => (await passthroughProbe({ port: proxyPort, sni: 'reload.test' })) > 0;

	before(async () => {
		upstream = await startCountingUpstream();
		proxyPort = await getFreePort();
		proxy = new SymphonyProxy({ listeners: [{ host: '127.0.0.1', port: proxyPort }], routes: routes() });
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await upstream.close();
	});

	it('applies added and removed entries to new connections', async () => {
		assert.equal(await admitted(), true);

		proxy.updateConfig({ routes: routes(['10.0.0.0/8']) });
		assert.equal(await admitted(), false);

		proxy.updateConfig({ routes: routes(['10.0.0.0/8', '127.0.0.1']) });
		assert.equal(await admitted(), true);

		proxy.updateConfig({ routes: routes(['10.0.0.0/8']) });
		assert.equal(await admitted(), false);

		proxy.updateConfig({ routes: routes() });
		assert.equal(await admitted(), true);

		const route = proxy.metrics().routeMetrics.find((r) => r.route === 'reload.test')!;
		assert.equal(route.blocked, 2, 'counters survive list-only reloads');
		assert.equal(route.connections, 5);
	});

	it('does not drop an established connection when its peer is removed from the list', async () => {
		const socket = net.createConnection({ port: proxyPort, host: '127.0.0.1' });
		await new Promise<void>((resolve) => socket.once('connect', () => resolve()));
		socket.write(clientHello('reload.test'));
		await new Promise<void>((resolve) => socket.once('data', () => resolve()));

		proxy.updateConfig({ routes: routes(['10.0.0.0/8']) });
		const echoed = new Promise<Buffer>((resolve) => socket.once('data', resolve));
		socket.write('still here');
		assert.equal((await echoed).toString(), 'still here');
		socket.destroy();
	});
});

describe('allowedSources – invalid entries', () => {
	let upstream: CountingUpstream;
	let proxyPort: number;
	let proxy: SymphonyProxy;

	before(async () => {
		upstream = await startCountingUpstream();
		proxyPort = await getFreePort();
		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				passthroughRoute('*.tenants.test', upstream.port),
				passthroughRoute('bad.tenants.test', upstream.port, { allowedSources: ['127.0.0.1', '10.0.0.0/33'] }),
			],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await upstream.close();
	});

	it('drops only the route with the invalid entry, failing closed', async () => {
		assert.equal(proxy.metrics().failingRoutes, 1);
		const before = upstream.accepted();
		assert.equal(await passthroughProbe({ port: proxyPort, sni: 'bad.tenants.test' }), 0);
		assert.equal(upstream.accepted(), before, 'must not fall through to the wildcard');
		assert.ok((await passthroughProbe({ port: proxyPort, sni: 'good.tenants.test' })) > 0);
	});

	it('recovers once the entry is fixed', async () => {
		proxy.updateConfig({
			routes: [
				passthroughRoute('*.tenants.test', upstream.port),
				passthroughRoute('bad.tenants.test', upstream.port, { allowedSources: ['127.0.0.1', '10.0.0.0/8'] }),
			],
		});
		assert.equal(proxy.metrics().failingRoutes, 0);
		assert.ok((await passthroughProbe({ port: proxyPort, sni: 'bad.tenants.test' })) > 0);
	});
});

describe('allowedSources – suspended routes', () => {
	let upstream: CountingUpstream;
	let proxyPort: number;
	let proxy: SymphonyProxy;
	const suspended: SuspendedConnection[] = [];
	const errors: Error[] = [];
	let resolveWith: (conn: SuspendedConnection) => void = () => {};
	const held = (sni: string, allowedSources?: string[]): RouteConfig => ({
		sni,
		upstreams: [],
		terminateTls: false,
		suspended: true,
		suspendTimeoutMs: 2000,
		allowedSources,
	});

	before(async () => {
		upstream = await startCountingUpstream();
		proxyPort = await getFreePort();
		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [held('held.test'), held('held-local.test', ['127.0.0.1']), held('held-closed.test', DENY_LOCAL)],
		});
		proxy.on('suspended', (conn: SuspendedConnection) => {
			suspended.push(conn);
			resolveWith(conn);
		});
		proxy.on('error', (err: Error) => errors.push(err));
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await upstream.close();
	});

	const resolved = (allowedSources?: string[]) => (conn: SuspendedConnection) =>
		proxy.resolveConnection(conn.id, {
			upstream: { kind: 'tcp', host: '127.0.0.1', port: upstream.port },
			terminateTls: false,
			allowedSources,
		});

	it('refuses a peer outside the static list before suspending it', async () => {
		resolveWith = resolved(); // a permissive resolution must not get the chance to admit it
		const before = suspended.length;
		assert.equal(await passthroughProbe({ port: proxyPort, sni: 'held-closed.test' }), 0);
		assert.equal(suspended.length, before, "no 'suspended' event for a refused peer");
		assert.equal(routeBlocked(proxy, 'held-closed.test'), 1);
	});

	it('enforces the resolution list after resolveConnection()', async () => {
		resolveWith = resolved(['10.0.0.0/8']);
		const before = upstream.accepted();
		assert.equal(await passthroughProbe({ port: proxyPort, sni: 'held.test' }), 0);
		await sleep(50);
		assert.equal(upstream.accepted(), before);
		assert.equal(routeBlocked(proxy, 'held.test'), 1);
		assert.equal(proxy.metrics().pendingSuspended, 0);
	});

	it('admits a peer matching the resolution list', async () => {
		resolveWith = resolved(['127.0.0.1']);
		assert.ok((await passthroughProbe({ port: proxyPort, sni: 'held.test' })) > 0);
	});

	it('applies both lists when both are set', async () => {
		resolveWith = resolved(DENY_LOCAL);
		assert.equal(await passthroughProbe({ port: proxyPort, sni: 'held-local.test' }), 0);
		resolveWith = resolved(['127.0.0.0/8']);
		assert.ok((await passthroughProbe({ port: proxyPort, sni: 'held-local.test' })) > 0);
	});

	it('rejects a resolution with an invalid entry and reports it', async () => {
		resolveWith = resolved(['not-a-cidr']);
		const before = upstream.accepted();
		const errorsBefore = errors.length;
		assert.equal(await passthroughProbe({ port: proxyPort, sni: 'held.test' }), 0);
		await sleep(50);
		assert.equal(upstream.accepted(), before);
		assert.equal(errors.length, errorsBefore + 1);
		assert.match(errors.at(-1)!.message, /not-a-cidr/);
		assert.equal(proxy.metrics().pendingSuspended, 0);
	});
});

describe('allowedSources – HTTP listener ACME proxy', () => {
	let acmeUpstream: net.Server;
	let acmeAccepted = 0;
	let httpPort: number;
	let proxy: SymphonyProxy;

	before(async () => {
		acmeUpstream = net.createServer((socket) => {
			acmeAccepted++;
			socket.on('error', () => {});
			socket.once('data', () => socket.end('HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok'));
		});
		await new Promise<void>((resolve) => acmeUpstream.listen(0, '127.0.0.1', () => resolve()));
		const acmePort = (acmeUpstream.address() as net.AddressInfo).port;
		httpPort = await getFreePort();
		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: httpPort, mode: 'http' }],
			routes: [
				passthroughRoute('acme.test', acmePort, { allowedSources: ['127.0.0.1'] }),
				passthroughRoute('acme-closed.test', acmePort, { allowedSources: DENY_LOCAL }),
			],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await new Promise<void>((resolve) => acmeUpstream.close(() => resolve()));
	});

	function challenge(host: string): Promise<string> {
		return new Promise((resolve, reject) => {
			let body = '';
			const socket = net.createConnection({ port: httpPort, host: '127.0.0.1' }, () =>
				socket.write(`GET /.well-known/acme-challenge/token HTTP/1.1\r\nHost: ${host}\r\n\r\n`)
			);
			socket.on('data', (chunk) => (body += chunk.toString()));
			socket.on('error', (err) => (socket.connecting ? reject(err) : undefined));
			socket.on('close', () => resolve(body));
			setTimeout(() => {
				socket.destroy();
				reject(new Error('challenge timeout'));
			}, 5000).unref();
		});
	}

	it('proxies the challenge for a listed peer', async () => {
		assert.match(await challenge('acme.test'), /200 OK/);
		assert.equal(acmeAccepted, 1);
	});

	it('refuses an unlisted peer without opening the upstream', async () => {
		assert.equal(await challenge('acme-closed.test'), '');
		assert.equal(acmeAccepted, 1);
		assert.equal(routeBlocked(proxy, 'acme-closed.test'), 1);
	});
});
