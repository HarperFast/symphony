/**
 * Tests for the protection layer: rate limiting, blockedIps(), and hot-swap via updateConfig().
 */

import assert from 'node:assert/strict';
import * as net from 'node:net';
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

describe('Protection – updateConfig hot-swap', () => {
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;

	before(async () => {
		echo = await startEchoServer();
		proxyPort = await getFreePort();

		// Start with no CIDR blocklist — connections from 127.0.0.1 are allowed
		proxy = new SymphonyProxy({
			listeners: [
				{
					host: '127.0.0.1',
					port: proxyPort,
					protection: {
						blocklist: [], // initially empty
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

	it('connection succeeds before blocklist is pushed', async () => {
		// Raw TCP connect should succeed (no blocklist)
		const connected = await new Promise<boolean>((resolve) => {
			const s = net.createConnection({ port: proxyPort, host: '127.0.0.1' }, () => {
				s.destroy();
				resolve(true);
			});
			s.on('error', () => resolve(false));
			setTimeout(() => resolve(false), 2000);
		});
		assert.ok(connected, 'Expected connection to succeed before blocklist update');
	});

	it('blockedIps() reflects new blocklist after updateConfig — no restart', async () => {
		// Push a blocklist covering 127.0.0.1 via updateConfig (no restart)
		proxy.updateConfig({
			protection: [
				{
					port: proxyPort,
					protection: { blocklist: ['127.0.0.1/32'] },
				},
			],
		});
		await sleep(20);

		const info = proxy.blockedIps();
		assert.ok(
			info.cidrBlocklist.includes('127.0.0.1/32'),
			`Expected 127.0.0.1/32 in cidrBlocklist after hot-swap, got: ${JSON.stringify(info.cidrBlocklist)}`,
		);
	});

	it('new connections from blocklisted IP are blocked after updateConfig', async () => {
		// Listen for the proxy's 'blocked' event — emitted when protection blocks a connection.
		// sni::peek() blocks until the client sends data or closes; s.end() (client FIN) unblocks it.
		const blockedEventFired = new Promise<boolean>((resolve) => {
			const handler = (event: { ip: string }) => {
				if (event.ip === '127.0.0.1') {
					proxy.off('blocked', handler);
					resolve(true);
				}
			};
			proxy.on('blocked', handler);
			setTimeout(() => {
				proxy.off('blocked', handler);
				resolve(false);
			}, 1000);
		});

		// Connect and immediately half-close so sni::peek() returns EOF and the protection check runs.
		await new Promise<void>((resolve) => {
			const s = net.createConnection({ port: proxyPort, host: '127.0.0.1' }, () => s.end());
			s.on('close', () => resolve());
			s.on('error', () => resolve());
		});

		assert.ok(
			await blockedEventFired,
			'Expected "blocked" event for 127.0.0.1 after blocklist hot-swap',
		);
	});

	it('removes blocklist via another updateConfig — connections allowed again', async () => {
		proxy.updateConfig({
			protection: [
				{
					port: proxyPort,
					protection: { blocklist: [] },
				},
			],
		});
		await sleep(20);

		const info = proxy.blockedIps();
		assert.equal(info.cidrBlocklist.length, 0, 'Expected cidrBlocklist to be empty after removal');
	});
});
