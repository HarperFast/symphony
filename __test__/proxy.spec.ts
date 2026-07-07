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
