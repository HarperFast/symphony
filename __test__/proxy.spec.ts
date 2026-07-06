/**
 * Integration tests for SymphonyProxy — TLS termination, passthrough, and hot config.
 *
 * These tests require the native addon to be built:
 *   npm run build:debug
 */

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import { generateSelfSignedCert, getFreePort, startEchoServer, tlsRoundTrip, sleep } from './util.js';

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

describe('SymphonyProxy – one poisoned route does not sink the listener', () => {
	const good = generateSelfSignedCert('good.example.com');
	const other = generateSelfSignedCert('bad.example.com');
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;

	before(async () => {
		echo = await startEchoServer();
		proxyPort = await getFreePort();

		// The first route pairs one cert with a *different* key — the exact inconsistency a cert
		// renewal produces when an inline chain is left pointing at a rotated key file. rustls
		// rejects it with KeyMismatch. Building routes eagerly, symphony used to let that abort the
		// whole proxy; now the bad route is skipped and its co-tenant on the same listener survives.
		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'bad.example.com',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					cert: { certChain: other.cert, privateKey: good.key }, // mismatched pair
				},
				{
					sni: 'good.example.com',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					cert: { certChain: good.cert, privateKey: good.key },
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

	it('constructs despite the mismatched-cert route', () => {
		// Reaching here at all means construction did not throw KeyMismatch.
		assert.ok(proxy);
	});

	it('still serves the co-tenant route on the same listener', async () => {
		const payload = Buffer.from('survivor');
		const response = await tlsRoundTrip({
			port: proxyPort,
			servername: 'good.example.com',
			caCert: good.cert,
			data: payload,
			rejectUnauthorized: true,
		});
		assert.deepEqual(response, payload);
	});
});
