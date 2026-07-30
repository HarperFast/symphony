/**
 * Integration tests for route-level protocol declaration (issue #38).
 *
 * Header rewriting (X-Forwarded-For / X-JA3 / X-JA4 injection) must be gated on an explicit
 * `protocol: 'http'` declaration rather than inferred from ALPN — ALPN alone can't tell a
 * native non-HTTP client (which negotiates no ALPN, e.g. MQTT) from an HTTPS client that
 * simply offered none. An `'opaque'` (default) route must proxy any byte stream verbatim,
 * without ever entering the HTTP/1 header rewriter.
 *
 * These tests require the native addon to be built:
 *   npm run build:debug
 */

import assert from 'node:assert/strict';
import * as tls from 'node:tls';
import { after, before, describe, it } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import { generateSelfSignedCert, getFreePort, startCaptureServer, startEchoServer, tlsRoundTrip, sleep } from './util.js';

/** Open a TLS connection through the proxy, send `data`, and resolve once written. */
function tlsSend(port: number, servername: string, caCert: string, data: Buffer | string): Promise<tls.TLSSocket> {
	return new Promise((resolve, reject) => {
		const socket = tls.connect({ port, host: '127.0.0.1', servername, ca: caCert, rejectUnauthorized: false }, () => {
			socket.write(data, () => resolve(socket));
		});
		socket.on('error', reject);
	});
}

describe('SymphonyProxy – route protocol declaration', () => {
	const cert = generateSelfSignedCert('localhost');

	// Opaque-route smoke test, not a regression test for the fix itself: this route has neither
	// `sourceAddressHeader` nor `forwardFingerprint` configured, so `header_rewrites()` returns
	// empty regardless of the `RouteProtocol::Http && !negotiated_h2` gate — it would pass
	// against the pre-fix ALPN heuristic too. It still earns its keep as an end-to-end sanity
	// check that a terminated non-HTTP byte stream (MQTT over TLS is the motivating case, issue
	// #38) round-trips promptly through `copy_bidirectional` with no header framing assumed.
	// Regression coverage for the runtime gate itself — `eligible_for_header_rewriting` — lives
	// in `src/proxy_conn.rs`'s unit tests (`opaque_protocol_is_never_eligible_regardless_of_alpn`,
	// `http_protocol_with_negotiated_h2_is_not_eligible`).
	it('smoke test: an opaque route proxies a non-HTTP byte stream end-to-end without hanging on HTTP framing', async () => {
		const upstream = await startEchoServer();
		const proxyPort = await getFreePort();
		// A short idle timeout: if the connection were mistakenly fed to the header rewriter,
		// it would stall waiting for a request terminator and get dropped once this elapses.
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort, idleTimeoutMs: 2000 }],
			routes: [
				{
					sni: 'mqtt.example.com',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: upstream.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
					// protocol left unset — defaults to 'opaque'.
				},
			],
		});
		await proxy.start();
		await sleep(50);

		// MQTT v3.1.1 CONNECT packet (fixed header + variable header + payload), no HTTP framing.
		const mqttConnect = Buffer.from([
			0x10, 0x0c, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
		]);

		// No separate timing assertion needed: if this were mistakenly fed to the header rewriter,
		// it would stall waiting for a request terminator that never arrives, and the 2000ms idle
		// timeout above would make this `await` reject (or return truncated/empty bytes) well before
		// the deepEqual below could pass. A load-dependent wall-clock bound would only add flakiness.
		const response = await tlsRoundTrip({
			port: proxyPort,
			servername: 'mqtt.example.com',
			caCert: cert.cert,
			data: mqttConnect,
		});

		assert.deepEqual(
			response,
			mqttConnect,
			'raw MQTT bytes proxied verbatim — no header injected, no HTTP parsing attempted'
		);

		await proxy.stop();
		await upstream.close();
	});

	it('an explicitly opaque route with PROXY protocol forwards the source address and the raw bytes unrewritten', async () => {
		const capture = await startCaptureServer();
		const proxyPort = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'mqtt.example.com',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: capture.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
					sourceAddressHeader: 'proxyProtocol',
					protocol: 'opaque',
				},
			],
		});
		await proxy.start();
		await sleep(50);

		const mqttConnect = Buffer.from([
			0x10, 0x0c, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00,
		]);
		const socket = await tlsSend(proxyPort, 'mqtt.example.com', cert.cert, mqttConnect);
		const received = await capture.received;

		assert.match(received.toString('latin1'), /^PROXY TCP4 127\.0\.0\.1 127\.0\.0\.1 \d+ \d+\r\n/, 'PROXY v1 header prefixes the stream');
		assert.ok(received.subarray(received.length - mqttConnect.length).equals(mqttConnect), 'raw MQTT bytes follow the header unmodified');

		socket.destroy();
		await proxy.stop();
		await capture.close();
	});

	it('a protocol: "http" route still injects X-Forwarded-For and strips a client-supplied one', async () => {
		const capture = await startCaptureServer();
		const proxyPort = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'app.example.com',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: capture.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
					sourceAddressHeader: 'xForwardedFor',
					protocol: 'http',
				},
			],
		});
		await proxy.start();
		await sleep(50);

		const spoofed = 'GET / HTTP/1.1\r\nHost: app.example.com\r\nX-Forwarded-For: 9.9.9.9\r\n\r\n';
		const socket = await tlsSend(proxyPort, 'app.example.com', cert.cert, spoofed);
		const text = (await capture.received).toString('ascii');

		assert.match(text, /\r\nX-Forwarded-For: 127\.0\.0\.1\r\n/, 'authoritative X-Forwarded-For injected');
		assert.ok(!text.includes('9.9.9.9'), 'spoofed X-Forwarded-For stripped');
		assert.equal((text.match(/X-Forwarded-For:/gi) ?? []).length, 1, 'exactly one X-Forwarded-For header');

		socket.destroy();
		await proxy.stop();
		await capture.close();
	});

	it('rejects xForwardedFor without a protocol: "http" declaration at construction time (fail loud, not a silent no-op)', async () => {
		assert.throws(
			() =>
				new SymphonyProxy({
					listeners: [{ host: '127.0.0.1', port: 0 }],
					routes: [
						{
							sni: 'mqtt.example.com',
							upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: 1 }],
							terminateTls: true,
							cert: { certChain: cert.cert, privateKey: cert.key },
							sourceAddressHeader: 'xForwardedFor',
							// protocol left unset — defaults to 'opaque', must be rejected, not silently accepted.
						},
					],
				}),
			/protocol/i,
			'construction must throw a descriptive error, not silently build a route that never injects the header'
		);
	});

	// A passthrough route (terminateTls: false, e.g. an MQTT-over-TLS route) never decrypts the
	// stream, so a header-carried forwardFingerprint mode has no carrier at all — no `protocol`
	// declaration can fix that. This must be rejected as a distinct "no carrier" error, not
	// steered toward `protocol: 'http'` (which is both semantically wrong for an opaque
	// passthrough route and, since header injection genuinely can't happen without termination,
	// would still not make the config work).
	it('rejects forwardFingerprint on a passthrough route as having no carrier, regardless of protocol declaration', async () => {
		const baseRoute = {
			sni: 'mqtt.example.com',
			upstreams: [{ kind: 'tcp' as const, host: '127.0.0.1', port: 1 }],
			terminateTls: false,
			forwardFingerprint: 'ja3' as const,
		};

		assert.throws(
			() =>
				new SymphonyProxy({
					listeners: [{ host: '127.0.0.1', port: 0 }],
					routes: [baseRoute],
				}),
			/no carrier/i,
			'passthrough + header-carried forwardFingerprint must fail construction with a "no carrier" error'
		);

		assert.throws(
			() =>
				new SymphonyProxy({
					listeners: [{ host: '127.0.0.1', port: 0 }],
					routes: [{ ...baseRoute, protocol: 'http' }],
				}),
			/no carrier/i,
			'declaring protocol: "http" must not paper over a passthrough route with no header carrier'
		);
	});

	// resolveConnection() parses and validates its `route` argument independently of the
	// suspended-connection id (parse_resolve_spec runs before the id is even looked up), so these
	// checks can be exercised directly against a fresh proxy without a real suspended connection.
	//
	// Unlike the static route table, an invalid resolveConnection() route must never *throw*: the
	// call is documented to happen from inside a 'suspended' listener (sync or async), and a thrown
	// exception there has no safe path back to the caller — an async listener's rejection is never
	// awaited by EventEmitter, and even a synchronous throw only reaches user code if an 'error'
	// listener happens to be attached. So a validation failure instead drops the connection (the
	// same outcome as resolveConnection(id, null)) and surfaces the reason via the 'error' event.
	describe('resolveConnection() protocol validation (symmetric with the static route table, fails via "error" event not a throw)', () => {
		let proxy: SymphonyProxy;

		before(() => {
			proxy = new SymphonyProxy({ listeners: [{ host: '127.0.0.1', port: 0 }], routes: [] });
		});

		/** Call resolveConnection with `route` and resolve with the message of the next 'error' event. */
		function resolveAndCaptureError(id: string, route: Parameters<SymphonyProxy['resolveConnection']>[1]): Promise<string> {
			return new Promise((resolve, reject) => {
				proxy.once('error', (err: Error) => resolve(err.message));
				try {
					proxy.resolveConnection(id, route);
				} catch (e) {
					reject(new Error(`resolveConnection() must never throw for a validation failure: ${e}`));
				}
			});
		}

		it('rejects xForwardedFor without a protocol: "http" declaration', async () => {
			const message = await resolveAndCaptureError('1', {
				upstream: { kind: 'tcp', host: '127.0.0.1', port: 1 },
				terminateTls: true,
				sourceAddressHeader: 'xForwardedFor',
			});
			assert.match(message, /protocol/i, 'resolveConnection must reject an undeclared xForwardedFor route just like the static route table');
		});

		it('rejects a header-carried forwardFingerprint on a passthrough route as having no carrier', async () => {
			const message = await resolveAndCaptureError('2', {
				upstream: { kind: 'tcp', host: '127.0.0.1', port: 1 },
				terminateTls: false,
				forwardFingerprint: 'ja3',
				protocol: 'http',
			});
			assert.match(
				message,
				/no carrier/i,
				'resolveConnection must reject passthrough + header-carried forwardFingerprint just like the static route table'
			);
		});

		it('rejects xForwardedFor combined with http2 (header injection would corrupt h2 frames)', async () => {
			const message = await resolveAndCaptureError('3', {
				upstream: { kind: 'tcp', host: '127.0.0.1', port: 1 },
				terminateTls: true,
				sourceAddressHeader: 'xForwardedFor',
				protocol: 'http',
				http2: true,
			});
			assert.match(
				message,
				/http2/i,
				'resolveConnection must reject xForwardedFor + http2 just like build_route does for the static route table'
			);
		});
	});
});
