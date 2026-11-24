/**
 * Holding clients whose certificate fails verification (`mtls.failureHoldMs`): the handshake
 * completes, nothing is answered for the hold, the connection closes, and no upstream is touched.
 *
 * Requires the native addon:
 *   npm run build:debug
 */

import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import * as tls from 'node:tls';
import { after, before, describe, it } from 'node:test';
import { renderPrometheus } from '../ts/admin.js';
import { SymphonyProxy } from '../ts/proxy.js';
import type { ProtectionConfig, RouteConfig } from '../ts/types.js';
import { generateSelfSignedCert, getFreePort, issueCert, sleep, type IssuedCert } from './util.js';

const HOLD_MS = 1200;
/** A rejection answered at once arrives well inside this; a held one well after it. */
const PROMPT_MS = 600;

const server = generateSelfSignedCert('localhost');
const ca = issueCert({ subject: 'Tarpit Test CA', ca: true });
const otherCa = issueCert({ subject: 'Unrelated CA', ca: true });
const valid = issueCert({ subject: 'valid-device', issuer: ca });
const expired = issueCert({
	subject: 'expired-device',
	issuer: ca,
	notBefore: new Date(Date.now() - 2 * 86_400_000),
	notAfter: new Date(Date.now() - 86_400_000),
});
const unknownIssuer = issueCert({ subject: 'unknown-device', issuer: otherCa });

interface CountingUpstream {
	port: number;
	accepted: () => number;
	close(): Promise<void>;
}

/** An echo server that counts the connections it accepts: a held client must never reach one. */
function startCountingUpstream(): Promise<CountingUpstream> {
	let accepted = 0;
	const sockets = new Set<net.Socket>();
	const srv = net.createServer((socket) => {
		accepted++;
		sockets.add(socket);
		socket.on('close', () => sockets.delete(socket));
		socket.on('error', () => {});
		socket.pipe(socket);
	});
	return new Promise((resolve) =>
		srv.listen(0, '127.0.0.1', () =>
			resolve({
				port: (srv.address() as net.AddressInfo).port,
				accepted: () => accepted,
				close: () =>
					new Promise((res) => {
						for (const s of sockets) s.destroy();
						srv.close(() => res());
					}),
			})
		)
	);
}

interface Attempt {
	/** ms from connect to the client's handshake completing; undefined if it never did. */
	secureAt?: number;
	/** ms from connect to the first data, error, end or close after the handshake. */
	firstEventAt?: number;
	closedAt: number;
	bytes: number;
	error?: Error;
	reused: boolean;
	session?: Buffer;
	/** Session tickets (TLS 1.3) or sessions (TLS 1.2) the server issued on this connection. */
	tickets: number;
}

/**
 * Connect, present `cert`, send an application request once the handshake completes (as an MQTT
 * or WebSocket client does), and record what comes back and when the connection ends.
 */
function attempt(
	port: number,
	opts: {
		cert?: IssuedCert;
		/** Leaf plus intermediates, when the chain has more than the leaf. */
		chain?: string;
		maxVersion?: 'TLSv1.2' | 'TLSv1.3';
		session?: Buffer;
		servername?: string;
	} = {}
): Promise<Attempt> {
	return new Promise((resolve) => {
		const start = Date.now();
		const result: Attempt = { closedAt: 0, bytes: 0, reused: false, tickets: 0 };
		const mark = () => (result.firstEventAt ??= Date.now() - start);
		const socket = tls.connect(
			{
				host: '127.0.0.1',
				port,
				servername: opts.servername ?? 'localhost',
				rejectUnauthorized: false,
				cert: opts.chain ?? opts.cert?.cert,
				key: opts.cert?.key,
				minVersion: 'TLSv1.2',
				maxVersion: opts.maxVersion ?? 'TLSv1.3',
				session: opts.session,
			},
			() => {
				result.secureAt = Date.now() - start;
				result.reused = socket.isSessionReused();
				result.session ??= socket.getSession() ?? undefined;
				socket.write('CONNECT\r\n');
			}
		);
		socket.on('session', (s: Buffer) => {
			result.session = s;
			result.tickets++;
		});
		socket.on('data', (d: Buffer) => {
			mark();
			result.bytes += d.length;
			socket.end();
		});
		socket.on('error', (e) => {
			mark();
			result.error ??= e;
		});
		socket.on('end', mark);
		const safety = setTimeout(() => socket.destroy(new Error('attempt never closed')), 15_000);
		socket.on('close', () => {
			mark();
			clearTimeout(safety);
			result.closedAt = Date.now() - start;
			resolve(result);
		});
	});
}

function assertHeld(a: Attempt, holdMs = HOLD_MS): void {
	assert.ok(a.secureAt !== undefined, `the client's handshake must complete (error: ${a.error?.message})`);
	assert.equal(a.bytes, 0, 'a held client must receive no application bytes');
	const silence = a.firstEventAt! - a.secureAt!;
	assert.ok(
		silence >= holdMs - 150,
		`nothing may reach the client during the hold, got an event after ${silence}ms (${a.error?.message})`
	);
	assert.ok(a.closedAt <= a.secureAt! + holdMs + 2000, `the hold must end, closed after ${a.closedAt}ms`);
	assert.doesNotMatch(a.error?.message ?? '', /alert/i, 'a held client must not get an alert');
}

function assertPromptAlert(a: Attempt, alert: RegExp): void {
	assert.ok(a.closedAt < PROMPT_MS, `expected an immediate rejection, closed after ${a.closedAt}ms`);
	assert.equal(a.bytes, 0);
	assert.match(a.error?.message ?? '', alert);
}

function assertPromptCloseWithoutAlert(a: Attempt): void {
	assert.ok(a.secureAt !== undefined, 'the handshake completes before the check runs');
	assert.ok(a.closedAt < PROMPT_MS, `expected an immediate close, closed after ${a.closedAt}ms`);
	assert.equal(a.bytes, 0);
	assert.doesNotMatch(a.error?.message ?? '', /alert/i);
}

function route(upstreamPort: number, mtls: RouteConfig['mtls'], sni = 'localhost'): RouteConfig {
	return {
		sni,
		upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: upstreamPort }],
		terminateTls: true,
		cert: { certChain: server.cert, privateKey: server.key },
		mtls,
	};
}

const reasons = (counts: { reason: string; count: number }[]) =>
	Object.fromEntries(counts.filter((c) => c.count > 0).map((c) => [c.reason, c.count]));

async function waitFor(predicate: () => boolean, what: string, timeoutMs = 5000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!predicate()) {
		if (Date.now() > deadline) throw new Error(`timed out waiting for ${what}`);
		await sleep(20);
	}
}

async function startProxy(routes: RouteConfig[], protection?: ProtectionConfig, mtls?: RouteConfig['mtls']) {
	const port = await getFreePort();
	const proxy = new SymphonyProxy({
		listeners: [{ host: '127.0.0.1', port, protection, mtls }],
		routes,
		workerThreads: 2,
	});
	await proxy.start();
	await sleep(50);
	return { port, proxy, held: () => proxy.metrics().listeners[0].heldConnections };
}

describe('mtls.failureHoldMs', () => {
	let upstream: CountingUpstream;
	before(async () => {
		upstream = await startCountingUpstream();
	});
	after(async () => {
		await upstream?.close();
	});

	describe('a required-certificate route with a hold', () => {
		let port: number;
		let proxy: SymphonyProxy;
		let held: () => number;
		before(async () => {
			({ port, proxy, held } = await startProxy([
				route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true, failureHoldMs: HOLD_MS, failureHoldJitter: 0 }),
			]));
		});
		after(async () => {
			await proxy?.stop();
		});

		for (const maxVersion of ['TLSv1.3', 'TLSv1.2'] as const) {
			it(`holds a ${maxVersion} client with an expired certificate, then closes it`, async () => {
				const accepted = upstream.accepted();
				assertHeld(await attempt(port, { cert: expired, maxVersion }));
				assert.equal(upstream.accepted(), accepted, 'a rejected client must never reach the upstream');
			});
		}

		it('holds a client whose certificate has an unknown issuer', async () => {
			const accepted = upstream.accepted();
			assertHeld(await attempt(port, { cert: unknownIssuer }));
			assert.equal(upstream.accepted(), accepted);
		});

		it('proxies a valid client from the same address while another is held', async () => {
			const holding = attempt(port, { cert: expired });
			await waitFor(() => held() === 1, 'the expired client to be held');
			const ok = await attempt(port, { cert: valid });
			assert.ok(ok.bytes > 0, `the valid client must be proxied (${ok.error?.message})`);
			assert.equal(held(), 1, 'the other client is still held');
			assertHeld(await holding);
		});

		it('alerts a client that presents no certificate at once, as before', async () => {
			assertPromptAlert(await attempt(port), /alert/i);
		});

		it('counts each rejection under its reason and reports held connections', async () => {
			const before = proxy.metrics();
			const holding = [attempt(port, { cert: expired }), attempt(port, { cert: unknownIssuer })];
			await waitFor(() => held() === 2, 'both clients to be held');
			const during = proxy.metrics();
			const exposition = renderPrometheus({
				pid: process.pid,
				version: 'test',
				startedAt: new Date().toISOString(),
				reloadedAt: new Date().toISOString(),
				proxies: [{ ports: String(port), metrics: during }],
			});
			assert.match(exposition, /^symphony_listener_held_connections\{[^}]*\} 2$/m, 'the gauge is exported');
			await Promise.all(holding);
			await attempt(port);
			const afterwards = proxy.metrics();
			assert.equal(afterwards.listeners[0].heldConnections, 0, 'the gauge returns to 0');

			const delta = (m: typeof before, r: string) => {
				const was = before.listeners[0].errorsByReason.find((c) => c.reason === r)!.count;
				return m.listeners[0].errorsByReason.find((c) => c.reason === r)!.count - was;
			};
			assert.equal(delta(afterwards, 'client_cert_expired'), 1);
			assert.equal(delta(afterwards, 'client_cert_untrusted'), 1);
			assert.equal(delta(afterwards, 'client_cert_missing'), 1);
			assert.equal(delta(afterwards, 'tls_handshake'), 0, 'certificate rejections are not handshake errors');
			const routeReasons = reasons(afterwards.routeMetrics[0].errorsByReason);
			assert.ok(routeReasons.client_cert_expired >= 1 && routeReasons.client_cert_untrusted >= 1);
			assert.equal(
				afterwards.listeners[0].errors,
				afterwards.listeners[0].errorsByReason.reduce((sum, c) => sum + c.count, 0)
			);
		});

		it('spreads holds across the jitter range', async () => {
			const { port: jitterPort, proxy: jitterProxy } = await startProxy([
				route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true, failureHoldMs: 1000 }),
			]);
			try {
				const attempts = await Promise.all(Array.from({ length: 6 }, () => attempt(jitterPort, { cert: expired })));
				const holds = attempts.map((a) => a.closedAt - a.secureAt!);
				for (const hold of holds) {
					assert.ok(hold >= 450 && hold <= 1500 + 500, `each hold falls in 1000ms × [0.5, 1.5], got ${holds}`);
				}
				assert.ok(Math.max(...holds) - Math.min(...holds) >= 20, `holds must not all be equal, got ${holds}`);
			} finally {
				await jitterProxy.stop();
			}
		});

		it('releases a hold as soon as its client closes', async () => {
			const { port: longPort, proxy: longProxy } = await startProxy([
				route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true, failureHoldMs: 30_000 }),
			]);
			try {
				const socket = tls.connect({
					host: '127.0.0.1',
					port: longPort,
					servername: 'localhost',
					rejectUnauthorized: false,
					cert: expired.cert,
					key: expired.key,
				});
				socket.on('error', () => {});
				await new Promise((resolve) => socket.once('secureConnect', resolve));
				await waitFor(() => longProxy.metrics().listeners[0].heldConnections === 1, 'the hold');
				socket.destroy();
				await waitFor(() => longProxy.metrics().listeners[0].heldConnections === 0, 'the slot to be released', 1000);
			} finally {
				await longProxy.stop();
			}
		});

		it('ends every hold when the proxy stops', async () => {
			const { port: longPort, proxy: longProxy } = await startProxy([
				route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true, failureHoldMs: 30_000 }),
			]);
			const holding = attempt(longPort, { cert: expired });
			await waitFor(() => longProxy.metrics().listeners[0].heldConnections === 1, 'the hold');
			const stoppedAt = Date.now();
			await longProxy.stop();
			const a = await holding;
			assert.equal(a.bytes, 0);
			assert.ok(Date.now() - stoppedAt < 2000, 'stop() must release the held socket');
		});
	});

	describe('resumed sessions', () => {
		let port: number;
		let proxy: SymphonyProxy;
		before(async () => {
			({ port, proxy } = await startProxy([
				route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true, failureHoldMs: HOLD_MS, failureHoldJitter: 0 }),
			]));
		});
		after(async () => {
			await proxy?.stop();
		});

		for (const maxVersion of ['TLSv1.3', 'TLSv1.2'] as const) {
			it(`holds a ${maxVersion} resumption whose certificate expired after the session was issued`, async () => {
				// root → intermediate → leaf, so a resumed chain must carry its intermediate to verify.
				const intermediate = issueCert({ subject: `Intermediate ${maxVersion}`, issuer: ca, ca: true });
				const notAfter = new Date(Math.ceil((Date.now() + 2500) / 1000) * 1000);
				const shortLived = issueCert({ subject: `short-lived ${maxVersion}`, issuer: intermediate, notAfter });
				const chain = shortLived.cert + intermediate.cert;

				const first = await attempt(port, { cert: shortLived, chain, maxVersion });
				assert.ok(first.bytes > 0, `a valid client is proxied (${first.error?.message})`);
				assert.ok(first.session, 'the server issued a session');

				const resumedWhileValid = await attempt(port, { cert: shortLived, chain, maxVersion, session: first.session });
				assert.equal(resumedWhileValid.reused, true);
				assert.ok(resumedWhileValid.bytes > 0, 'a valid resumed session is proxied');

				await sleep(Math.max(0, notAfter.getTime() + 1100 - Date.now()));
				const accepted = upstream.accepted();
				const resumedAfterExpiry = await attempt(port, {
					cert: shortLived,
					chain,
					maxVersion,
					session: resumedWhileValid.session ?? first.session,
				});
				assert.equal(resumedAfterExpiry.reused, true, 'the session must actually resume');
				assertHeld(resumedAfterExpiry);
				assert.equal(upstream.accepted(), accepted, 'a resumed session with an expired cert reaches no upstream');
			});
		}

		it('does not resume a session issued to a rejected client once the hold is turned off', async () => {
			const heldAttempt = await attempt(port, { cert: expired });
			assertHeld(heldAttempt);
			assert.ok(heldAttempt.tickets > 0, 'a held TLS 1.3 client was sent a ticket');
			const resumedHeld = await attempt(port, { cert: expired, session: heldAttempt.session });
			assert.equal(resumedHeld.reused, true, 'the ticket resumes on the holding config itself');
			assertHeld(resumedHeld);
			await proxy.updateConfig({
				routes: [route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true })],
			});
			try {
				const strict = await attempt(port, { cert: expired, session: heldAttempt.session });
				assert.equal(strict.reused, false, 'a ticket minted without the chain check must not resume on a strict config');
				assertPromptAlert(strict, /certificate expired/i);
			} finally {
				await proxy.updateConfig({
					routes: [
						route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true, failureHoldMs: HOLD_MS, failureHoldJitter: 0 }),
					],
				});
			}
		});
	});

	describe('configuration', () => {
		it('without a hold, alerts a rejected client at once and counts it by reason', async () => {
			const { port, proxy } = await startProxy([route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true })]);
			try {
				assertPromptAlert(await attempt(port, { cert: expired }), /certificate expired/i);
				assertPromptAlert(await attempt(port, { cert: unknownIssuer }), /unknown ca/i);
				assert.deepEqual(reasons(proxy.metrics().routeMetrics[0].errorsByReason), {
					client_cert_expired: 1,
					client_cert_untrusted: 1,
				});
			} finally {
				await proxy.stop();
			}
		});

		it('closes at once without an alert past maxHeldConnections, and the cap hot-swaps', async () => {
			const { port, proxy, held } = await startProxy(
				[route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true, failureHoldMs: HOLD_MS, failureHoldJitter: 0 })],
				{ maxHeldConnections: 1 }
			);
			try {
				const holding = attempt(port, { cert: expired });
				await waitFor(() => held() === 1, 'the first client to be held');
				assertPromptCloseWithoutAlert(await attempt(port, { cert: expired }));
				assert.equal(held(), 1);

				proxy.updateConfig({ protection: [{ port, protection: { maxHeldConnections: 2 } }] });
				assertHeld(await attempt(port, { cert: unknownIssuer }));
				await holding;

				proxy.updateConfig({ protection: [{ port, protection: { maxHeldConnections: 0 } }] });
				assertPromptCloseWithoutAlert(await attempt(port, { cert: expired }));
			} finally {
				await proxy.stop();
			}
		});

		it('counts held connections across listeners against each listener\'s cap', async () => {
			const [portA, portB] = [await getFreePort(), await getFreePort()];
			const proxy = new SymphonyProxy({
				listeners: [portA, portB].map((port) => ({
					host: '127.0.0.1',
					port,
					protection: { maxHeldConnections: 1 },
				})),
				routes: [
					route(upstream.port, {
						clientCaCert: ca.cert,
						requireClientCert: true,
						failureHoldMs: HOLD_MS,
						failureHoldJitter: 0,
					}),
				],
				workerThreads: 2,
			});
			await proxy.start();
			await sleep(50);
			try {
				const holding = attempt(portA, { cert: expired });
				await waitFor(() => proxy.metrics().listeners[0].heldConnections === 1, 'the hold on the first listener');
				assertPromptCloseWithoutAlert(await attempt(portB, { cert: expired }));
				assert.deepEqual(
					proxy.metrics().listeners.map((l) => l.heldConnections),
					[1, 0]
				);
				await holding;
			} finally {
				await proxy.stop();
			}
		});

		it('counts a held connection toward maxConcurrentPerIp', async () => {
			const { port, proxy, held } = await startProxy(
				[route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true, failureHoldMs: HOLD_MS, failureHoldJitter: 0 })],
				{ maxConcurrentPerIp: 1 }
			);
			try {
				const holding = attempt(port, { cert: expired });
				await waitFor(() => held() === 1, 'the hold');
				const refused = await attempt(port, { cert: valid });
				assert.equal(refused.bytes, 0, 'the held socket occupies the address\'s only slot');
				assert.equal(reasons(proxy.metrics().listeners[0].blockedByReason).too_many_connections, 1);
				await holding;
				await waitFor(() => held() === 0, 'the hold to end');
				await sleep(100);
				assert.ok((await attempt(port, { cert: valid })).bytes > 0, 'the slot is free once the hold ends');
			} finally {
				await proxy.stop();
			}
		});

		it('on an optional-certificate route, proxies a client with no certificate and holds a bad one', async () => {
			const { port, proxy } = await startProxy([
				route(upstream.port, { clientCaCert: ca.cert, requireClientCert: false, failureHoldMs: HOLD_MS, failureHoldJitter: 0 }),
			]);
			try {
				assert.ok((await attempt(port)).bytes > 0, 'no certificate is still allowed');
				assertHeld(await attempt(port, { cert: unknownIssuer }));
			} finally {
				await proxy.stop();
			}
		});

		it('opens no upstream for a rejected client on a failover route', async () => {
			const unusedPeer = await getFreePort();
			const { port, proxy } = await startProxy([
				{
					...route(upstream.port, { clientCaCert: ca.cert, requireClientCert: false, failureHoldMs: HOLD_MS, failureHoldJitter: 0 }),
					failover: { peers: [{ host: '127.0.0.1', port: unusedPeer }] },
				},
			]);
			try {
				const accepted = upstream.accepted();
				assertHeld(await attempt(port, { cert: expired }));
				assert.equal(upstream.accepted(), accepted, 'no early connect for a route that checks after the handshake');
				assert.ok((await attempt(port, { cert: valid })).bytes > 0);
			} finally {
				await proxy.stop();
			}
		});

		it('takes the hold from listener mtls exactly when the route inherits its CA', async () => {
			const { port, proxy } = await startProxy(
				[
					{ ...route(upstream.port, undefined), sni: 'inherits.test' },
					{ ...route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true }), sni: 'own.test' },
				],
				undefined,
				{ clientCaCert: ca.cert, requireClientCert: true, failureHoldMs: HOLD_MS, failureHoldJitter: 0 }
			);
			try {
				assertHeld(await attempt(port, { cert: expired, servername: 'inherits.test' }));
				assertPromptAlert(await attempt(port, { cert: expired, servername: 'own.test' }), /certificate expired/i);
			} finally {
				await proxy.stop();
			}
		});

		it('hot-swaps failureHoldMs through updateConfig', async () => {
			const { port, proxy } = await startProxy([route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true })]);
			try {
				assertPromptAlert(await attempt(port, { cert: expired }), /certificate expired/i);
				await proxy.updateConfig({
					routes: [route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true, failureHoldMs: HOLD_MS, failureHoldJitter: 0 })],
				});
				assertHeld(await attempt(port, { cert: expired }));
			} finally {
				await proxy.stop();
			}
		});

		it('serves a route with an invalid failureHoldMs without the hold, and counts it as failing', async () => {
			const { port, proxy } = await startProxy([
				route(upstream.port, { clientCaCert: ca.cert, requireClientCert: true, failureHoldMs: 600_001 }),
			]);
			try {
				assert.equal(proxy.metrics().failingRoutes, 1);
				assert.ok((await attempt(port, { cert: valid })).bytes > 0, 'the route still serves');
				assertPromptAlert(await attempt(port, { cert: expired }), /certificate expired/i);
			} finally {
				await proxy.stop();
			}
		});

		it('rejects an invalid maxHeldConnections', async () => {
			for (const maxHeldConnections of [-1, 1.5, Number.NaN]) {
				assert.throws(
					() =>
						new SymphonyProxy({
							listeners: [{ host: '127.0.0.1', port: 0, protection: { maxHeldConnections } }],
							routes: [],
						}),
					/maxHeldConnections/
				);
			}
		});

		it('holds on a route resolved by resolveConnection', async () => {
			const port = await getFreePort();
			const proxy = new SymphonyProxy({
				listeners: [{ host: '127.0.0.1', port }],
				routes: [{ sni: 'localhost', upstreams: [], terminateTls: false, suspended: true, suspendTimeoutMs: 5000 }],
			});
			let failureHoldMs: number = HOLD_MS;
			const errors: Error[] = [];
			proxy.on('error', (e) => errors.push(e));
			proxy.on('suspended', (conn) => {
				proxy.resolveConnection(conn.id, {
					upstream: { kind: 'tcp', host: '127.0.0.1', port: upstream.port },
					terminateTls: true,
					cert: { certChain: server.cert, privateKey: server.key },
					mtls: { clientCaCert: ca.cert, requireClientCert: true, failureHoldMs, failureHoldJitter: 0 },
				});
			});
			await proxy.start();
			await sleep(50);
			try {
				const accepted = upstream.accepted();
				assertHeld(await attempt(port, { cert: expired }));
				assert.equal(upstream.accepted(), accepted);
				assert.ok((await attempt(port, { cert: valid })).bytes > 0);

				failureHoldMs = -1;
				const rejected = await attempt(port, { cert: valid });
				assert.equal(rejected.bytes, 0, 'an invalid resolution closes the connection');
				assert.match(errors.map((e) => e.message).join('\n'), /failureHoldMs/);
			} finally {
				await proxy.stop();
			}
		});
	});

	it('symphony-server passes failureHoldMs from its config file', async () => {
		const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-tarpit-'));
		const caFile = path.join(dir, 'ca.pem');
		fs.writeFileSync(caFile, ca.cert);
		const port = await getFreePort();
		const configPath = path.join(dir, 'config.json');
		fs.writeFileSync(
			configPath,
			JSON.stringify({
				version: 1,
				proxies: [
					{
						listeners: [{ host: '127.0.0.1', port }],
						routes: [
							{
								...route(upstream.port, undefined),
								mtls: { clientCaCertFile: caFile, requireClientCert: true, failureHoldMs: HOLD_MS, failureHoldJitter: 0 },
							},
							{
								...route(upstream.port, undefined, 'typo.test'),
								mtls: { clientCaCertFile: caFile, requireClientCert: true, failureHoldMs: '5000' },
							},
						],
					},
				],
			})
		);
		const child = spawn(process.execPath, [path.join(__dirname, '..', 'ts', 'server.js'), '--config', configPath], {
			stdio: 'ignore',
		});
		try {
			const deadline = Date.now() + 10_000;
			let up = await attempt(port, { cert: valid });
			while (up.bytes === 0 && Date.now() < deadline) {
				await sleep(100);
				up = await attempt(port, { cert: valid });
			}
			assert.ok(up.bytes > 0, 'symphony-server came up');
			assertHeld(await attempt(port, { cert: expired }));
			assertPromptAlert(
				await attempt(port, { cert: expired, servername: 'typo.test' }),
				/certificate expired/i
			);
		} finally {
			child.kill('SIGTERM');
			fs.rmSync(dir, { recursive: true, force: true });
		}
	});
});
