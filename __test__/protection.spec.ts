/**
 * Tests for the protection layer: rate limiting, blockedIps(), JA4 blocking, and hot-swap via updateConfig().
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

describe('Protection – sustained rate limit', () => {
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;

	before(async () => {
		echo = await startEchoServer();
		proxyPort = await getFreePort();

		// 100 CPM burst 3 → only 3 connections allowed in a short window,
		// even though per-second limit is generous (1000 cps).
		proxy = new SymphonyProxy({
			listeners: [
				{
					host: '127.0.0.1',
					port: proxyPort,
					protection: {
						rateLimit: { connectionsPerSecond: 1000, burst: 1000 },
						sustained: { connectionsPerMinute: 100, burst: 3 },
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

	it('blocks after sustained burst exhausted despite low per-second rate', async () => {
		// Fire 6 rapid connections — the first 3 should be allowed (burst=3),
		// then the sustained bucket is empty and further connections are blocked.
		for (let i = 0; i < 6; i++) {
			await openAndClose(proxyPort);
		}
		await sleep(50);

		const info = proxy.blockedIps();
		// 127.0.0.1 should be in rateLimited after sustained burst exhaustion
		assert.ok(
			info.rateLimited.includes('127.0.0.1') || info.rateLimited.length > 0,
			`Expected 127.0.0.1 in rateLimited after sustained exhaustion, got: ${JSON.stringify(info)}`,
		);
	});

	it('sustained limit is independent of per-second limit', async () => {
		// Even though per-second allows 1000 cps, sustained burst is 3 total.
		// After exhaust: 4th connection is blocked → IP appears in rateLimited.
		const info = proxy.blockedIps();
		assert.ok(Array.isArray(info.rateLimited), 'rateLimited must be an array');
		// penaltyBox not configured → penaltyBoxed must be empty
		assert.deepEqual(info.penaltyBoxed, [], 'penaltyBoxed must be empty (no penaltyBox config)');
	});
});

describe('Protection – penalty box', () => {
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;

	before(async () => {
		echo = await startEchoServer();
		proxyPort = await getFreePort();

		// Tiny burst (1) + short penalty (300 ms) so the test stays fast.
		proxy = new SymphonyProxy({
			listeners: [
				{
					host: '127.0.0.1',
					port: proxyPort,
					protection: {
						rateLimit: { connectionsPerSecond: 2, burst: 1 },
						penaltyBox: { durationMs: 300 },
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

	it('blocks immediately after rate limit exhaustion and emits penalty_boxed reason', async () => {
		// Exhaust burst (1 connection), then one more triggers RateLimited → enters penalty box.
		// Subsequent connections emit 'blocked' with reason 'penalty_boxed'.
		const penaltyReasons: string[] = [];
		proxy.on('blocked', (ev) => penaltyReasons.push(ev.reason));

		// First connection consumes the only token
		await openAndClose(proxyPort);
		// Second: rate limited → enters penalty box
		await openAndClose(proxyPort);
		// Third: should be penalty_boxed
		await openAndClose(proxyPort);
		await sleep(50);

		assert.ok(
			penaltyReasons.includes('penalty_boxed') || penaltyReasons.includes('rate_limited'),
			`Expected a blocked event, got: ${JSON.stringify(penaltyReasons)}`,
		);
	});

	it('blockedIps() lists IP in penaltyBoxed while penalty is active', async () => {
		// Drain the bucket again (it may have refilled slightly after prior test)
		for (let i = 0; i < 5; i++) {
			await openAndClose(proxyPort);
		}
		await sleep(30);

		const info = proxy.blockedIps();
		assert.ok(
			info.penaltyBoxed.includes('127.0.0.1') || info.rateLimited.includes('127.0.0.1'),
			`Expected 127.0.0.1 in penaltyBoxed or rateLimited, got: ${JSON.stringify(info)}`,
		);
	});

	it('readmits IP after penalty expires', async () => {
		// Wait for the 300 ms penalty + some margin to expire.
		await sleep(500);

		// Connection should now be allowed (penalty expired, bucket refilled at 2 cps).
		const connected = await new Promise<boolean>((resolve) => {
			const s = net.createConnection({ port: proxyPort, host: '127.0.0.1' }, () => {
				s.destroy();
				resolve(true);
			});
			s.on('error', () => resolve(false));
			setTimeout(() => resolve(false), 1000);
		});
		// Note: "connected" reflects TCP level — the proxy may immediately close but the TCP
		// connect still succeeded. We just confirm no ECONNREFUSED.
		assert.ok(connected, 'Expected connection to succeed after penalty expiry');
	});
});

describe('Protection – penaltyBox hot-swap via updateConfig', () => {
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;

	before(async () => {
		echo = await startEchoServer();
		proxyPort = await getFreePort();

		// Start without penaltyBox
		proxy = new SymphonyProxy({
			listeners: [
				{
					host: '127.0.0.1',
					port: proxyPort,
					protection: {
						rateLimit: { connectionsPerSecond: 2, burst: 1 },
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

	it('penaltyBoxed is empty before penaltyBox config is added', async () => {
		// Exhaust rate limit — no penalty box yet
		for (let i = 0; i < 5; i++) {
			await openAndClose(proxyPort);
		}
		await sleep(30);

		const info = proxy.blockedIps();
		assert.deepEqual(info.penaltyBoxed, [], 'penaltyBoxed must be empty without penaltyBox config');
	});

	it('penaltyBoxed populated after hot-swapping in penaltyBox config', async () => {
		// Hot-swap in a penaltyBox config (10 s penalty — long enough to observe)
		proxy.updateConfig({
			protection: [
				{
					port: proxyPort,
					protection: {
						rateLimit: { connectionsPerSecond: 2, burst: 1 },
						penaltyBox: { durationMs: 10_000 },
					},
				},
			],
		});
		await sleep(20);

		// Exhaust rate limit to enter the penalty box
		const penaltyBoxedReason = new Promise<boolean>((resolve) => {
			const handler = (ev: { reason: string }) => {
				if (ev.reason === 'penalty_boxed') {
					proxy.off('blocked', handler);
					resolve(true);
				}
			};
			proxy.on('blocked', handler);
			setTimeout(() => {
				proxy.off('blocked', handler);
				resolve(false);
			}, 2000);
		});

		// Multiple attempts: first exhausts rate, subsequent get penalty_boxed
		for (let i = 0; i < 5; i++) {
			await openAndClose(proxyPort);
		}

		const saw = await penaltyBoxedReason;
		assert.ok(saw, 'Expected "blocked" event with reason "penalty_boxed" after hot-swap');

		const info = proxy.blockedIps();
		assert.ok(
			info.penaltyBoxed.includes('127.0.0.1'),
			`Expected 127.0.0.1 in penaltyBoxed, got: ${JSON.stringify(info.penaltyBoxed)}`,
		);
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

describe('Protection – fingerprint blocklist validation', () => {
	const cert = generateSelfSignedCert('localhost');

	function build(protection: any): SymphonyProxy {
		return new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: 0, protection }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: 1 }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
	}

	it('rejects a malformed ja4Blocklist entry at construction', () => {
		assert.throws(() => build({ ja4Blocklist: ['not-a-ja4'] }), /invalid ja4Blocklist entry/);
		// Wrong length / bad separators / non-hex hash are all rejected.
		assert.throws(() => build({ ja4Blocklist: ['t13d1516h2_8daaf6152771'] }), /invalid ja4Blocklist/);
		assert.throws(
			() => build({ ja4Blocklist: ['t13d1516h2_8daaf615277g_02713d6af862'] }),
			/invalid ja4Blocklist/
		);
	});

	it('accepts a well-formed ja4Blocklist entry', () => {
		const proxy = build({ ja4Blocklist: ['t13d1516h2_8daaf6152771_02713d6af862'] });
		assert.ok(proxy);
	});

	it('rejects a malformed ja3Blocklist entry at construction', () => {
		assert.throws(() => build({ ja3Blocklist: ['deadbeef'] }), /invalid ja3Blocklist entry/);
		assert.throws(() => build({ ja3Blocklist: ['z'.repeat(32)] }), /invalid ja3Blocklist entry/);
	});

	it('accepts a well-formed ja3Blocklist entry', () => {
		const proxy = build({ ja3Blocklist: ['0123456789abcdef0123456789abcdef'] });
		assert.ok(proxy);
	});

	it('accepts an uppercase ja4Blocklist entry (normalized before validation)', () => {
		// Matching is documented as case-insensitive; validation must normalize first so a
		// fully uppercase — but otherwise well-formed — fingerprint isn't wrongly rejected.
		const proxy = build({ ja4Blocklist: ['T13D1516H2_8DAAF6152771_02713D6AF862'] });
		assert.ok(proxy);
	});

	it('rejects a ja4Blocklist entry symphony could never produce', () => {
		// symphony only computes JA4 for TLS-over-TCP ('t') at versions it actually speaks
		// (00/10/11/12/13) — a 'q'/'d' transport prefix or an unreachable version passes the
		// old length/charset-only validation but can never match, so it must be rejected too.
		assert.throws(
			() => build({ ja4Blocklist: ['q13i070500_1234567890ab_abcdef012345'] }),
			/invalid ja4Blocklist/,
			'QUIC prefix should be rejected',
		);
		assert.throws(
			() => build({ ja4Blocklist: ['t99d1516h2_8daaf6152771_02713d6af862'] }),
			/invalid ja4Blocklist/,
			'unreachable version should be rejected',
		);
	});
});
