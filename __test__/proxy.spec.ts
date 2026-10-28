/**
 * Integration tests for SymphonyProxy — TLS termination, passthrough, and hot config.
 *
 * These tests require the native addon to be built:
 *   npm run build:debug
 */

import assert from 'node:assert/strict';
import * as net from 'node:net';
import { after, before, describe, it } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import {
	generateSelfSignedCert,
	getFreePort,
	startEchoServer,
	tcpRoundTrip,
	tlsRoundTrip,
	tlsAlpn,
	sleep,
} from './util.js';

describe('SymphonyProxy – TLS termination', () => {
	const cert = generateSelfSignedCert('localhost');
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;

	before(async () => {
		echo = await startEchoServer();
		proxyPort = await getFreePort();

		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await echo.close();
	});

	it('proxies data through TLS termination to TCP upstream', async () => {
		const payload = Buffer.from('hello-symphony');
		const response = await tlsRoundTrip({
			port: proxyPort,
			servername: 'localhost',
			caCert: cert.cert,
			data: payload,
			rejectUnauthorized: true,
		});
		assert.deepEqual(response, payload);
	});

	it('metrics() shows active = 0 after connection closes', async () => {
		await sleep(50);
		const m = proxy.metrics();
		assert.equal(m.activeConnections, 0);
	});
});

describe('SymphonyProxy – http2 ALPN', () => {
	// Regression: toJsRoute() used to drop `http2`, so `http2: true` never reached
	// Rust and no route ever advertised h2 in ALPN.
	const cert = generateSelfSignedCert('localhost');
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;

	before(async () => {
		echo = await startEchoServer();
		proxyPort = await getFreePort();

		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'h2.localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					http2: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
				{
					sni: 'h1.localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await echo.close();
	});

	it('advertises h2 in ALPN when http2: true', async () => {
		const negotiated = await tlsAlpn({
			port: proxyPort,
			servername: 'h2.localhost',
			caCert: cert.cert,
			alpnProtocols: ['h2', 'http/1.1'],
		});
		assert.equal(negotiated, 'h2');
	});

	it('does not advertise h2 when http2 is unset (default)', async () => {
		const negotiated = await tlsAlpn({
			port: proxyPort,
			servername: 'h1.localhost',
			caCert: cert.cert,
			alpnProtocols: ['h2', 'http/1.1'],
		});
		assert.equal(negotiated, '');
	});

	it('picks up http2 through updateConfig', async () => {
		proxy.updateConfig({
			routes: [
				{
					sni: 'h1.localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					http2: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
		await sleep(20);

		const negotiated = await tlsAlpn({
			port: proxyPort,
			servername: 'h1.localhost',
			caCert: cert.cert,
			alpnProtocols: ['h2', 'http/1.1'],
		});
		assert.equal(negotiated, 'h2');
	});
});

describe('SymphonyProxy – wildcard SNI routing', () => {
	const cert = generateSelfSignedCert('test.example.com');
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;

	before(async () => {
		echo = await startEchoServer();
		proxyPort = await getFreePort();

		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: '*.example.com',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await echo.close();
	});

	it('matches wildcard SNI for sub-domains', async () => {
		const payload = Buffer.from('wildcard-test');
		const response = await tlsRoundTrip({
			port: proxyPort,
			servername: 'test.example.com',
			caCert: cert.cert,
			data: payload,
			rejectUnauthorized: false,
		});
		assert.deepEqual(response, payload);
	});
});

describe('SymphonyProxy – hot config updateConfig', () => {
	const certA = generateSelfSignedCert('service-a.test');
	const certB = generateSelfSignedCert('service-b.test');
	let proxyPort: number;
	let echoA: Awaited<ReturnType<typeof startEchoServer>>;
	let echoB: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;

	before(async () => {
		echoA = await startEchoServer();
		echoB = await startEchoServer();
		proxyPort = await getFreePort();

		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'service-a.test',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echoA.port }],
					terminateTls: true,
					cert: { certChain: certA.cert, privateKey: certA.key },
				},
			],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await echoA.close();
		await echoB.close();
	});

	it('routes to service-a before config update', async () => {
		const payload = Buffer.from('before-update');
		const response = await tlsRoundTrip({
			port: proxyPort,
			servername: 'service-a.test',
			caCert: certA.cert,
			data: payload,
			rejectUnauthorized: false,
		});
		assert.deepEqual(response, payload);
	});

	it('routes to new service after updateConfig', async () => {
		proxy.updateConfig({
			routes: [
				{
					sni: 'service-a.test',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echoA.port }],
					terminateTls: true,
					cert: { certChain: certA.cert, privateKey: certA.key },
				},
				{
					sni: 'service-b.test',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echoB.port }],
					terminateTls: true,
					cert: { certChain: certB.cert, privateKey: certB.key },
				},
			],
		});
		await sleep(20);

		const payload = Buffer.from('after-update');
		const response = await tlsRoundTrip({
			port: proxyPort,
			servername: 'service-b.test',
			caCert: certB.cert,
			data: payload,
			rejectUnauthorized: false,
		});
		assert.deepEqual(response, payload);
	});
});

describe('SymphonyProxy – updateConfig atomicity (routes + protection)', () => {
	// Regression for: combined update with valid routes + invalid protection must leave
	// BOTH in the old state. Previously routes were swapped before protection validation ran,
	// causing partial application on error.
	const certA = generateSelfSignedCert('atomicity-a.test');
	let proxyPort: number;
	let echoA: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;

	before(async () => {
		echoA = await startEchoServer();
		proxyPort = await getFreePort();

		proxy = new SymphonyProxy({
			listeners: [
				{
					host: '127.0.0.1',
					port: proxyPort,
					protection: { blocklist: [] },
				},
			],
			routes: [
				{
					sni: 'atomicity-a.test',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echoA.port }],
					terminateTls: true,
					cert: { certChain: certA.cert, privateKey: certA.key },
				},
			],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await echoA.close();
	});

	it('failed combined update (valid routes + invalid protection) leaves old routes serving', async () => {
		// Confirm the initial route serves.
		const before = await tlsRoundTrip({
			port: proxyPort,
			servername: 'atomicity-a.test',
			caCert: certA.cert,
			data: Buffer.from('before-atomic-test'),
			rejectUnauthorized: false,
		});
		assert.deepEqual(before, Buffer.from('before-atomic-test'), 'initial route must serve');

		// Combined update: routes would remove atomicity-a.test, protection references a non-existent port.
		// The call must throw and leave both routes AND protection unchanged.
		assert.throws(
			() =>
				proxy.updateConfig({
					routes: [
						{
							sni: 'atomicity-b.test', // replaces atomicity-a.test
							upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echoA.port }],
							terminateTls: false,
						},
					],
					protection: [
						{
							port: 9999, // valid u16, but no such listener → error
							protection: {},
						},
					],
				}),
			/port 9999 matches no listener/,
			'updateConfig must throw when protection references a non-existent port',
		);

		// Old route must still resolve — not replaced by atomicity-b.test.
		const after = await tlsRoundTrip({
			port: proxyPort,
			servername: 'atomicity-a.test',
			caCert: certA.cert,
			data: Buffer.from('after-atomic-fail'),
			rejectUnauthorized: false,
		});
		assert.deepEqual(
			after,
			Buffer.from('after-atomic-fail'),
			'old route must still serve after failed combined update',
		);
	});
});

describe('SymphonyProxy – start() binds every listener or none', () => {
	const connects = (port: number) =>
		new Promise<boolean>((resolve) => {
			const socket = net.createConnection({ port, host: '127.0.0.1' }, () => {
				socket.destroy();
				resolve(true);
			});
			socket.on('error', () => resolve(false));
		});

	it('rejects when one listener cannot bind, leaving the others closed, and can be retried', async () => {
		const echo = await startEchoServer();
		const freePort = await getFreePort();
		// Bound without SO_REUSEPORT, so symphony's bind on the same address fails.
		const blocker = net.createServer();
		await new Promise<void>((resolve) => blocker.listen(0, '127.0.0.1', resolve));
		const busyPort = (blocker.address() as net.AddressInfo).port;
		const proxy = new SymphonyProxy({
			listeners: [
				{ host: '127.0.0.1', port: freePort },
				{ host: '127.0.0.1', port: busyPort, mode: 'http' },
			],
			routes: [{ sni: '', upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }], terminateTls: false }],
		});
		try {
			await assert.rejects(proxy.start(), new RegExp(`listener 127\\.0\\.0\\.1:${busyPort}`));
			assert.equal(await connects(freePort), false, 'the listener that could bind must not be left open');

			await new Promise<void>((resolve) => blocker.close(() => resolve()));
			const first = proxy.start();
			assert.equal(proxy.start(), first, 'concurrent callers share one start');
			await first;
			assert.equal((await tcpRoundTrip({ port: freePort, data: 'ping' })).toString(), 'ping');
		} finally {
			blocker.close();
			await proxy.stop();
			await echo.close();
		}
	});
});

describe('SymphonyProxy – start() and stop() run in call order', () => {
	it('restarts when start() is called while a stop() is still draining', async () => {
		const echo = await startEchoServer();
		const port = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port }],
			routes: [{ sni: '', upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }], terminateTls: false }],
		});
		try {
			await proxy.start();
			const stopping = proxy.stop();
			const restarting = proxy.start();
			await Promise.all([stopping, restarting]);
			assert.equal((await tcpRoundTrip({ port, data: 'ping' })).toString(), 'ping');
		} finally {
			await proxy.stop();
			await echo.close();
		}
	});
});

// symphony#47
describe('SymphonyProxy – default route (sni: "")', () => {
	const cert = generateSelfSignedCert('localhost');
	const tlsCert = { certChain: cert.cert, privateKey: cert.key };
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	const proxies: SymphonyProxy[] = [];

	before(async () => {
		echo = await startEchoServer();
	});

	after(async () => {
		for (const proxy of proxies) await proxy.stop();
		await echo.close();
	});

	async function startProxy(config: ConstructorParameters<typeof SymphonyProxy>[0]): Promise<SymphonyProxy> {
		const proxy = new SymphonyProxy(config);
		proxies.push(proxy);
		await proxy.start();
		return proxy;
	}

	const upstreams = () => [{ kind: 'tcp' as const, host: '127.0.0.1', port: echo.port }];
	const connections = (proxy: SymphonyProxy, route: string) =>
		proxy.metrics().routeMetrics.find((r) => r.route === route)?.connections;
	const count = (counts: { reason: string; count: number }[], reason: string) =>
		counts.find((c) => c.reason === reason)?.count ?? 0;

	it('serves TLS clients with no SNI, or an SNI no route matches, from the default route', async () => {
		const port = await getFreePort();
		const proxy = await startProxy({
			listeners: [{ host: '127.0.0.1', port }],
			routes: [
				{ sni: 'localhost', upstreams: upstreams(), terminateTls: true, cert: tlsCert },
				{ sni: '', upstreams: upstreams(), terminateTls: true, cert: tlsCert },
			],
		});

		assert.equal((await tlsRoundTrip({ port, servername: '', data: 'no-sni' })).toString(), 'no-sni');
		assert.equal((await tlsRoundTrip({ port, servername: 'unknown.example', data: 'other' })).toString(), 'other');
		assert.equal((await tlsRoundTrip({ port, servername: 'localhost', data: 'exact' })).toString(), 'exact');

		assert.equal(connections(proxy, ''), 2);
		assert.equal(connections(proxy, 'localhost'), 1);
		assert.equal(proxy.metrics().routes, 2);
	});

	it('passes a client that sends no ClientHello through a passthrough default route', async () => {
		const port = await getFreePort();
		const proxy = await startProxy({
			listeners: [{ host: '127.0.0.1', port }],
			routes: [{ sni: '', upstreams: upstreams(), terminateTls: false }],
		});

		assert.equal((await tcpRoundTrip({ port, data: 'plain tcp' })).toString(), 'plain tcp');
		assert.equal(count(proxy.metrics().listeners[0].errorsByReason, 'no_route'), 0);
	});

	it('still blocks a client with no SNI as no_sni under requireSni', async () => {
		const port = await getFreePort();
		const proxy = await startProxy({
			listeners: [{ host: '127.0.0.1', port, protection: { requireSni: true } }],
			routes: [{ sni: '', upstreams: upstreams(), terminateTls: false }],
		});

		const reply = await tcpRoundTrip({ port, data: 'plain tcp' }).catch(() => Buffer.alloc(0));
		assert.equal(reply.length, 0);
		assert.equal(count(proxy.metrics().listeners[0].blockedByReason, 'no_sni'), 1);
	});
});
