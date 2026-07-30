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

	// The regression this whole issue is about: a terminated non-HTTP route (MQTT over TLS is
	// the motivating case) must proxy the decrypted byte stream verbatim and promptly. Under the
	// old ALPN heuristic (`alpn_protocol() != Some(b"h2")`), a terminated MQTT connection — which
	// negotiates no ALPN — was indistinguishable from an HTTP/1 client and could be fed to
	// `proxy_http1_rewriting`, which waits for a `\r\n\r\n` that never arrives (a hang, not an
	// error). An MQTT CONNECT packet is used as the payload: it starts with 0x10 (never an HTTP
	// method token) and contains no CRLFCRLF anywhere.
	it('an opaque route proxies a non-HTTP byte stream end-to-end without entering the header rewriter', async () => {
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

		const start = Date.now();
		const response = await tlsRoundTrip({
			port: proxyPort,
			servername: 'mqtt.example.com',
			caCert: cert.cert,
			data: mqttConnect,
		});
		const elapsedMs = Date.now() - start;

		assert.deepEqual(
			response,
			mqttConnect,
			'raw MQTT bytes proxied verbatim — no header injected, no HTTP parsing attempted'
		);
		assert.ok(
			elapsedMs < 1000,
			`round-trip must complete promptly, not stall waiting for an HTTP header terminator (took ${elapsedMs}ms)`
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
});
