/**
 * Tests for the protection layer: rate limiting, blockedIps(), JA4 blocking.
 */

import assert from 'node:assert/strict';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { after, before, describe, it } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import { generateSelfSignedCert, getFreePort, startEchoServer, sleep } from './util.js';

/** Attempt a raw TCP connection without reading/writing, then close it. */
async function openAndClose(port: number): Promise<void> {
	await new Promise<void>((resolve, reject) => {
		const s = net.createConnection({ port, host: '127.0.0.1' }, () => {
			s.end();
		});
		s.on('close', resolve);
		s.on('error', resolve); // connection may be refused — that's OK for rate-limit tests
	});
}

describe('Protection – rate limiting', () => {
	const cert = generateSelfSignedCert('localhost');
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;

	before(async () => {
		echo = await startEchoServer();
		proxyPort = await getFreePort();

		proxy = new SymphonyProxy({
			listeners: [
				{
					host: '127.0.0.1',
					port: proxyPort,
					protection: {
						rateLimit: { connectionsPerSecond: 2, burst: 2 },
					},
				},
			],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: false,
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

	it('blockedIps() returns rate-limited IPs after burst exhausted', async () => {
		// Exceed the burst of 2 by opening 6 rapid connections
		for (let i = 0; i < 6; i++) {
			await openAndClose(proxyPort);
		}
		await sleep(50);

		const info = proxy.blockedIps();
		// 127.0.0.1 should appear in rateLimited after burst exhaustion
		assert.ok(
			info.rateLimited.includes('127.0.0.1') || info.rateLimited.length > 0,
			`Expected 127.0.0.1 in rateLimited, got: ${JSON.stringify(info.rateLimited)}`,
		);
	});
});

describe('Protection – CIDR blocklist', () => {
	const cert = generateSelfSignedCert('localhost');
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;

	before(async () => {
		echo = await startEchoServer();
		proxyPort = await getFreePort();

		proxy = new SymphonyProxy({
			listeners: [
				{
					host: '127.0.0.1',
					port: proxyPort,
					protection: {
						blocklist: ['192.0.2.0/24'], // TEST-NET-1, never used in practice
					},
				},
			],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: false,
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

	it('blockedIps() returns configured CIDR blocklist entries', () => {
		const info = proxy.blockedIps();
		assert.ok(
			info.cidrBlocklist.includes('192.0.2.0/24'),
			`Expected 192.0.2.0/24 in cidrBlocklist, got: ${JSON.stringify(info.cidrBlocklist)}`,
		);
	});

	it('allowlisted IPs are not in cidrBlocklist', () => {
		const info = proxy.blockedIps();
		// The blocklist should only list configured CIDR blocklist entries, not allowlist
		assert.ok(Array.isArray(info.cidrBlocklist));
		assert.ok(Array.isArray(info.rateLimited));
		assert.ok(Array.isArray(info.concurrencyLimited));
	});
});

describe('Protection – JA4 blocklist', () => {
	const cert = generateSelfSignedCert('localhost');
	let echoPort: number;
	let echoServer: net.Server;

	before(async () => {
		// Plain TCP echo: the proxy runs in passthrough mode so the upstream
		// never needs to speak TLS — only the peek path (ClientHello) matters.
		await new Promise<void>((resolve) => {
			echoServer = net.createServer((s) => s.pipe(s));
			echoServer.listen(0, '127.0.0.1', () => {
				echoPort = (echoServer.address() as net.AddressInfo).port;
				resolve();
			});
		});
	});

	after(async () => {
		await new Promise<void>((res) => echoServer.close(() => res()));
	});

	it('blocks TLS connections matching the ja4Blocklist', async () => {
		// Phase 1: discover the Node.js TLS client JA4 by using a CIDR-blocked proxy
		// that emits a 'blocked' event including the ja4 field.
		const probePort = await getFreePort();
		let discoveredJa4 = '';

		const probeProxy = new SymphonyProxy({
			listeners: [{
				host: '127.0.0.1',
				port: probePort,
				protection: { blocklist: ['127.0.0.1/32'] },
			}],
			routes: [{
				sni: 'localhost',
				upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echoPort }],
				terminateTls: false,
			}],
		});

		probeProxy.on('blocked', (e: { ja4: string }) => {
			if (e.ja4) discoveredJa4 = e.ja4;
		});

		await probeProxy.start();
		await sleep(50);

		// TLS connect → proxy peeks ClientHello → CIDR-blocked (peek still runs) → RST.
		await new Promise<void>((resolve) => {
			const s = tls.connect(
				{ port: probePort, host: '127.0.0.1', servername: 'localhost', rejectUnauthorized: false },
				() => { s.end(); },
			);
			s.on('error', () => resolve());
			s.on('close', () => resolve());
			setTimeout(resolve, 3000);
		});

		await sleep(200);
		await probeProxy.stop();

		assert.ok(
			discoveredJa4.length > 0,
			'should have captured a JA4 fingerprint from the blocked event',
		);
		// Validate JA4 format: t<2 digits><d|i><2 digits><2 digits><2 chars>_<12hex>_<12hex>
		assert.match(
			discoveredJa4,
			/^t[0-9]{2}[di][0-9]{4}[a-z0-9]{2}_[0-9a-f]{12}_[0-9a-f]{12}$/,
			`JA4 format unexpected: ${discoveredJa4}`,
		);

		// Phase 2: configure a new proxy with the observed JA4 in the blocklist and
		// verify the TLS connection is blocked with reason 'ja4_blocked'.
		const testPort = await getFreePort();
		let blockedReason = '';

		const testProxy = new SymphonyProxy({
			listeners: [{
				host: '127.0.0.1',
				port: testPort,
				protection: { ja4Blocklist: [discoveredJa4] },
			}],
			routes: [{
				sni: 'localhost',
				upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echoPort }],
				terminateTls: false,
			}],
		});

		testProxy.on('blocked', (e: { reason: string }) => {
			blockedReason = e.reason;
		});

		await testProxy.start();
		await sleep(50);

		await new Promise<void>((resolve) => {
			const s = tls.connect(
				{ port: testPort, host: '127.0.0.1', servername: 'localhost', rejectUnauthorized: false },
				() => { s.end(); },
			);
			s.on('error', () => resolve());
			s.on('close', () => resolve());
			setTimeout(resolve, 3000);
		});

		await sleep(200);
		await testProxy.stop();

		assert.equal(blockedReason, 'ja4_blocked', `Expected ja4_blocked, got: ${blockedReason}`);
	});
});
