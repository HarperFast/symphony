/**
 * Integration tests for PROXY protocol v2 emission and downstream JA3/JA4 fingerprint
 * forwarding (issue #9).
 *
 * These tests require the native addon to be built:
 *   npm run build:debug
 */

import assert from 'node:assert/strict';
import * as tls from 'node:tls';
import { after, before, describe, it } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import {
	generateSelfSignedCert,
	getFreePort,
	startCaptureServer,
	startTlsEchoServer,
	tlsRoundTrip,
	sleep,
} from './util.js';

const PROXY_V2_SIGNATURE = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]);
const PP2_TYPE_JA3 = 0xe0;

interface ParsedV2 {
	command: number;
	famProto: number;
	srcIp: string;
	srcPort: number;
	tlvs: Map<number, Buffer>;
	rest: Buffer;
}

/** Parse a PROXY protocol v2 header (IPv4 only, sufficient for these localhost tests). */
function parseProxyV2(buf: Buffer): ParsedV2 {
	assert.ok(buf.subarray(0, 12).equals(PROXY_V2_SIGNATURE), 'v2 signature');
	const command = buf[12];
	const famProto = buf[13];
	const len = buf.readUInt16BE(14);
	const body = buf.subarray(16, 16 + len);
	assert.equal(famProto, 0x11, 'AF_INET | STREAM');
	const srcIp = `${body[0]}.${body[1]}.${body[2]}.${body[3]}`;
	const srcPort = body.readUInt16BE(8);
	// TLVs begin after the 12-byte IPv4 address block.
	const tlvs = new Map<number, Buffer>();
	let off = 12;
	while (off + 3 <= body.length) {
		const type = body[off];
		const tlvLen = body.readUInt16BE(off + 1);
		tlvs.set(type, body.subarray(off + 3, off + 3 + tlvLen));
		off += 3 + tlvLen;
	}
	return { command, famProto, srcIp, srcPort, tlvs, rest: buf.subarray(16 + len) };
}

/** Open a TLS connection through the proxy, send `data`, and resolve once written. */
function tlsSend(port: number, servername: string, caCert: string, data: string): Promise<tls.TLSSocket> {
	return new Promise((resolve, reject) => {
		const socket = tls.connect({ port, host: '127.0.0.1', servername, ca: caCert, rejectUnauthorized: false }, () => {
			socket.write(data, () => resolve(socket));
		});
		socket.on('error', reject);
	});
}

const HTTP_REQUEST = 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n';

describe('PROXY protocol v2 + fingerprint forwarding', () => {
	const cert = generateSelfSignedCert('localhost');

	it('emits a v2 header carrying the JA3 fingerprint as a TLV', async () => {
		const capture = await startCaptureServer();
		const proxyPort = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: capture.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
					sourceAddressHeader: 'proxyProtocolV2',
					forwardFingerprint: 'ja3',
				},
			],
		});
		await proxy.start();
		await sleep(50);

		const socket = await tlsSend(proxyPort, 'localhost', cert.cert, HTTP_REQUEST);
		const received = await capture.received;
		const parsed = parseProxyV2(received);

		assert.equal(parsed.command, 0x21, 'version 2 | PROXY command');
		assert.equal(parsed.srcIp, '127.0.0.1', 'source IP is the real client');
		const ja3 = parsed.tlvs.get(PP2_TYPE_JA3);
		assert.ok(ja3, 'JA3 TLV present');
		assert.match(ja3!.toString('ascii'), /^[0-9a-f]{32}$/, 'JA3 is a 32-char md5 hex');
		assert.equal(parsed.rest.toString('ascii'), HTTP_REQUEST, 'application data follows the header');

		socket.destroy();
		await proxy.stop();
		await capture.close();
	});

	it('emits no fingerprint TLV when forwardFingerprint is off (TLS-facts TLVs still present)', async () => {
		const capture = await startCaptureServer();
		const proxyPort = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: capture.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
					sourceAddressHeader: 'proxyProtocolV2',
				},
			],
		});
		await proxy.start();
		await sleep(50);

		const socket = await tlsSend(proxyPort, 'localhost', cert.cert, HTTP_REQUEST);
		const parsed = parseProxyV2(await capture.received);
		// No fingerprint (0xE0/0xE1) or client cert (0xE2) TLVs — but terminated PP2
		// connections always carry the TLS-facts TLVs (authority 0x02, SSL 0x20, ALPN 0x01).
		assert.ok(!parsed.tlvs.has(0xe0), 'no JA3 TLV without forwardFingerprint');
		assert.ok(!parsed.tlvs.has(0xe1), 'no JA4 TLV without forwardFingerprint');
		assert.ok(!parsed.tlvs.has(0xe2), 'no client cert TLV without a client cert');
		assert.equal(parsed.tlvs.get(0x02)?.toString(), 'localhost', 'SNI authority TLV');
		assert.ok(parsed.tlvs.has(0x20), 'SSL TLV present on terminated connections');
		assert.equal(parsed.rest.toString('ascii'), HTTP_REQUEST);

		socket.destroy();
		await proxy.stop();
		await capture.close();
	});

	it('injects an X-JA3 header alongside X-Forwarded-For for L7 upstreams', async () => {
		const capture = await startCaptureServer();
		const proxyPort = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: capture.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
					sourceAddressHeader: 'xForwardedFor',
					forwardFingerprint: 'ja3',
					protocol: 'http',
				},
			],
		});
		await proxy.start();
		await sleep(50);

		const socket = await tlsSend(proxyPort, 'localhost', cert.cert, HTTP_REQUEST);
		const text = (await capture.received).toString('ascii');

		assert.match(text, /\r\nX-Forwarded-For: 127\.0\.0\.1\r\n/, 'X-Forwarded-For injected');
		assert.match(text, /\r\nX-JA3: [0-9a-f]{32}\r\n/, 'X-JA3 injected after the request line');
		assert.ok(text.startsWith('GET / HTTP/1.1\r\n'), 'request line preserved');

		socket.destroy();
		await proxy.stop();
		await capture.close();
	});

	// Passthrough forwards raw TLS bytes to a TLS upstream. A header carrier must be a no-op here:
	// splicing X-JA3 into the ClientHello ciphertext would break the upstream handshake. A working
	// end-to-end round-trip proves nothing was injected.
	it('does not inject a fingerprint header in passthrough mode', async () => {
		const upstream = await startTlsEchoServer(cert.cert, cert.key);
		const proxyPort = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: upstream.port }],
					terminateTls: false,
					forwardFingerprint: 'ja3',
					// protocol: 'http' declared even though passthrough can never actually inject a
					// header (there's no decrypted HTTP request to rewrite) — the point of this test is
					// that the carrier is a runtime no-op regardless of the declaration.
					protocol: 'http',
				},
			],
		});
		await proxy.start();
		await sleep(50);

		const payload = Buffer.from('passthrough-ok');
		const response = await tlsRoundTrip({
			port: proxyPort,
			servername: 'localhost',
			caCert: cert.cert,
			data: payload,
		});
		assert.deepEqual(response, payload, 'end-to-end TLS round-trip intact (no injected header)');

		await proxy.stop();
		await upstream.close();
	});

	// Finding 1 (Critical — Slowloris): a client that completes the TLS handshake and then stalls
	// without sending any HTTP request must be dropped once the idle timeout elapses, not held open
	// forever. The header read now lives inside the idle-timeout-bounded copy.
	it('drops a client that stalls post-TLS without sending a request', async () => {
		const capture = await startCaptureServer();
		const proxyPort = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort, idleTimeoutMs: 300 }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: capture.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
					sourceAddressHeader: 'xForwardedFor',
					forwardFingerprint: 'ja3',
					protocol: 'http',
				},
			],
		});
		await proxy.start();
		await sleep(50);

		// Complete the TLS handshake but never send an HTTP request.
		const socket = await new Promise<tls.TLSSocket>((resolve, reject) => {
			const s = tls.connect(
				{ port: proxyPort, host: '127.0.0.1', servername: 'localhost', ca: cert.cert, rejectUnauthorized: false },
				() => resolve(s)
			);
			s.on('error', reject);
		});

		const closedInTime = await new Promise<boolean>((resolve) => {
			const guard = setTimeout(() => resolve(false), 2000);
			socket.on('close', () => {
				clearTimeout(guard);
				resolve(true);
			});
		});
		assert.ok(closedInTime, 'proxy dropped the stalled connection after the idle timeout');

		socket.destroy();
		await proxy.stop();
		await capture.close();
	});

	// Finding 2 (High): a client-supplied X-JA3 / X-Forwarded-For must be stripped end-to-end so the
	// injected values are authoritative and cannot be spoofed.
	it('strips client-supplied fingerprint and forwarded-for headers', async () => {
		const capture = await startCaptureServer();
		const proxyPort = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: capture.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
					sourceAddressHeader: 'xForwardedFor',
					forwardFingerprint: 'ja3',
					protocol: 'http',
				},
			],
		});
		await proxy.start();
		await sleep(50);

		const spoofed =
			'GET / HTTP/1.1\r\nHost: localhost\r\nX-JA3: deadbeefdeadbeefdeadbeefdeadbeef\r\n' +
			'X-Forwarded-For: 9.9.9.9\r\n\r\n';
		const socket = await tlsSend(proxyPort, 'localhost', cert.cert, spoofed);
		const text = (await capture.received).toString('ascii');

		assert.match(text, /\r\nX-JA3: [0-9a-f]{32}\r\n/, 'authoritative X-JA3 present');
		assert.match(text, /\r\nX-Forwarded-For: 127\.0\.0\.1\r\n/, 'authoritative X-Forwarded-For present');
		assert.ok(!text.includes('deadbeef'), 'spoofed X-JA3 stripped');
		assert.ok(!text.includes('9.9.9.9'), 'spoofed X-Forwarded-For stripped');
		assert.equal((text.match(/X-JA3:/gi) ?? []).length, 1, 'exactly one X-JA3');

		socket.destroy();
		await proxy.stop();
		await capture.close();
	});

	// Finding 2 (keep-alive): every request on a keep-alive connection is rewritten, so a spoofed
	// header on a *second* pipelined request is stripped too — not just the first read.
	it('injects and strips on every pipelined keep-alive request', async () => {
		const capture = await startCaptureServer();
		const proxyPort = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: capture.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
					sourceAddressHeader: 'xForwardedFor',
					forwardFingerprint: 'ja3',
					protocol: 'http',
				},
			],
		});
		await proxy.start();
		await sleep(50);

		const pipelined =
			'GET /one HTTP/1.1\r\nHost: localhost\r\n\r\n' +
			'GET /two HTTP/1.1\r\nHost: localhost\r\nX-JA3: spoofed0000000000000000000000000\r\n\r\n';
		const socket = await tlsSend(proxyPort, 'localhost', cert.cert, pipelined);
		const text = (await capture.received).toString('ascii');

		assert.ok(text.includes('GET /one HTTP/1.1\r\n'), 'first request forwarded');
		assert.ok(text.includes('GET /two HTTP/1.1\r\n'), 'second request forwarded');
		assert.equal((text.match(/X-JA3: [0-9a-f]{32}\r\n/g) ?? []).length, 2, 'both requests get an authoritative X-JA3');
		assert.ok(!text.includes('spoofed'), 'spoofed X-JA3 on the second request is stripped');

		socket.destroy();
		await proxy.stop();
		await capture.close();
	});

	// XFF + h2 rejection at config time is covered by h2-dispatch.spec.ts (route dropped).
	// With http2 advertised the client negotiates h2, so the upstream receives binary h2 frames.
	// The fingerprint header carrier must be a runtime no-op on the negotiated-h2 connection —
	// the captured bytes must be exactly what the client sent.
	it('negotiates h2 and does not inject the fingerprint header into the HTTP/2 stream', async () => {
		const capture = await startCaptureServer();
		const proxyPort = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: capture.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
					http2: true,
					sourceAddressHeader: 'none',
					forwardFingerprint: 'ja3',
					protocol: 'http',
				},
			],
		});
		await proxy.start();
		await sleep(50);

		const preface = 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n';
		let socket!: tls.TLSSocket;
		const alpn = await new Promise<string | false | null>((resolve, reject) => {
			socket = tls.connect(
				{
					port: proxyPort,
					host: '127.0.0.1',
					servername: 'localhost',
					ALPNProtocols: ['h2', 'http/1.1'],
					ca: cert.cert,
					rejectUnauthorized: false,
				},
				() => {
					socket.write(preface);
					resolve(socket.alpnProtocol);
				}
			);
			socket.on('error', reject);
		});

		assert.equal(alpn, 'h2', 'route.http2 must reach ALPN so h2 negotiates');
		const received = (await capture.received).toString('ascii');
		assert.equal(received, preface, 'the h2 stream is forwarded verbatim — no header spliced in');

		socket.destroy();
		await proxy.stop();
		await capture.close();
	});
});
