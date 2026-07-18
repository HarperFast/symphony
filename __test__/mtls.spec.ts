/**
 * Integration tests for mTLS termination + PROXY protocol v2 client-cert forwarding.
 *
 * These tests require the native addon to be built:
 *   npm run build:debug
 *
 * Skipped entirely when openssl is unavailable (client CA generation needs it).
 */

import assert from 'node:assert/strict';
import * as crypto from 'node:crypto';
import * as net from 'node:net';
import { after, before, describe, it } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import { generateClientCa, generateSelfSignedCert, getFreePort, sleep, tlsRoundTrip } from './util.js';

// ── PROXY protocol v2 parsing (test-side consumer) ─────────────────────────────

const PP2_SIGNATURE = Buffer.from([0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a]);
const PP2_TYPE_ALPN = 0x01;
const PP2_TYPE_AUTHORITY = 0x02;
const PP2_TYPE_SSL = 0x20;
const PP2_SUBTYPE_SSL_VERSION = 0x21;
const PP2_TYPE_CLIENT_CERT = 0xe2;
const PP2_CLIENT_SSL = 0x01;
const PP2_CLIENT_CERT_CONN = 0x02;

interface Tlv {
	type: number;
	value: Buffer;
}

interface Pp2Header {
	family: number;
	srcIp: string;
	srcPort: number;
	totalLength: number;
	tlvs: Tlv[];
}

function parseTlvs(buf: Buffer): Tlv[] {
	const tlvs: Tlv[] = [];
	let off = 0;
	while (off < buf.length) {
		const type = buf[off];
		const len = buf.readUInt16BE(off + 1);
		tlvs.push({ type, value: buf.subarray(off + 3, off + 3 + len) });
		off += 3 + len;
	}
	assert.equal(off, buf.length, 'TLV block has trailing bytes');
	return tlvs;
}

function parsePp2(buf: Buffer): Pp2Header {
	assert.ok(buf.subarray(0, 12).equals(PP2_SIGNATURE), 'PROXY v2 signature mismatch');
	assert.equal(buf[12], 0x21, 'expected v2 PROXY command');
	const family = buf[13];
	const len = buf.readUInt16BE(14);
	let srcIp = '';
	let srcPort = 0;
	let addrLen = 0;
	if (family === 0x11) {
		addrLen = 12;
		srcIp = Array.from(buf.subarray(16, 20)).join('.');
		srcPort = buf.readUInt16BE(24);
	} else if (family === 0x21) {
		addrLen = 36;
	} else {
		assert.fail(`unexpected PP2 family 0x${family.toString(16)}`);
	}
	const tlvs = parseTlvs(buf.subarray(16 + addrLen, 16 + len));
	return { family, srcIp, srcPort, totalLength: 16 + len, tlvs };
}

// ── Upstream that captures the PP2 header and echoes the app payload ──────────

interface Pp2Capture {
	header: Pp2Header;
	appData: Buffer;
}

interface Pp2CaptureServer {
	port: number;
	nextConnection(): Promise<Pp2Capture>;
	close(): Promise<void>;
}

/**
 * TCP server that parses a leading PROXY v2 header, echoes everything after it
 * (so client round-trips complete), and reports the capture once app data arrives.
 */
function startPp2CaptureServer(): Promise<Pp2CaptureServer> {
	const pending: ((c: Pp2Capture) => void)[] = [];
	const ready: Pp2Capture[] = [];
	return new Promise((resolve, reject) => {
		const server = net.createServer((socket) => {
			let buffered = Buffer.alloc(0);
			let header: Pp2Header | null = null;
			let reported = false;
			socket.on('data', (chunk: Buffer) => {
				if (header) {
					socket.write(chunk);
					if (!reported) {
						reported = true;
						const capture = { header, appData: chunk };
						const waiter = pending.shift();
						if (waiter) waiter(capture);
						else ready.push(capture);
					}
					return;
				}
				buffered = Buffer.concat([buffered, chunk]);
				if (buffered.length < 16) return;
				const total = 16 + buffered.readUInt16BE(14);
				if (buffered.length < total) return;
				header = parsePp2(buffered);
				const appData = buffered.subarray(total);
				if (appData.length > 0) {
					socket.write(appData);
					reported = true;
					const capture = { header, appData };
					const waiter = pending.shift();
					if (waiter) waiter(capture);
					else ready.push(capture);
				}
			});
		});
		server.listen(0, '127.0.0.1', () => {
			const { port } = server.address() as net.AddressInfo;
			resolve({
				port,
				nextConnection: () =>
					new Promise<Pp2Capture>((res, rej) => {
						const timer = setTimeout(() => rej(new Error('nextConnection timeout')), 5000);
						const deliver = (c: Pp2Capture) => {
							clearTimeout(timer);
							res(c);
						};
						const queued = ready.shift();
						if (queued) deliver(queued);
						else pending.push(deliver);
					}),
				close: () => new Promise((res, rej) => server.close((e) => (e ? rej(e) : res()))),
			});
		});
		server.on('error', reject);
	});
}

// ── Tests ──────────────────────────────────────────────────────────────────────

const clientCa = generateClientCa();

describe('mTLS termination + PROXY v2 client cert forwarding', () => {
	const serverCert = generateSelfSignedCert('localhost');
	let proxyPort: number;
	let upstream: Pp2CaptureServer;
	let proxy: SymphonyProxy;

	before(async () => {
		upstream = await startPp2CaptureServer();
		proxyPort = await getFreePort();

		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: upstream.port }],
					terminateTls: true,
					cert: { certChain: serverCert.cert, privateKey: serverCert.key },
					mtls: { clientCaCert: clientCa.caCert, requireClientCert: true },
					sourceAddressHeader: 'proxyProtocolV2',
				},
				{
					sni: 'optional.localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: upstream.port }],
					terminateTls: true,
					cert: { certChain: serverCert.cert, privateKey: serverCert.key },
					mtls: { clientCaCert: clientCa.caCert, requireClientCert: false },
					sourceAddressHeader: 'proxyProtocolV2',
				},
			],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await upstream.close();
	});

	it('forwards the verified client cert chain via PP2 TLVs', async () => {
		const payload = Buffer.from('hello-mtls');
		const [response, capture] = await Promise.all([
			tlsRoundTrip({
				port: proxyPort,
				servername: 'localhost',
				caCert: serverCert.cert,
				clientCert: clientCa.clientCert,
				clientKey: clientCa.clientKey,
				data: payload,
			}),
			upstream.nextConnection(),
		]);
		assert.deepEqual(response, payload);
		assert.deepEqual(capture.appData, payload, 'app data must follow the header intact');

		const { header } = capture;
		assert.equal(header.family, 0x11);
		assert.equal(header.srcIp, '127.0.0.1');
		assert.ok(header.srcPort > 0);

		const authority = header.tlvs.find((t) => t.type === PP2_TYPE_AUTHORITY);
		assert.equal(authority?.value.toString(), 'localhost');

		const ssl = header.tlvs.find((t) => t.type === PP2_TYPE_SSL);
		assert.ok(ssl, 'SSL TLV missing');
		assert.equal(ssl.value[0] & PP2_CLIENT_SSL, PP2_CLIENT_SSL);
		assert.equal(ssl.value[0] & PP2_CLIENT_CERT_CONN, PP2_CLIENT_CERT_CONN);
		assert.equal(ssl.value.readUInt32BE(1), 0, 'verify must be 0 (verified)');
		const subTlvs = parseTlvs(ssl.value.subarray(5));
		const version = subTlvs.find((t) => t.type === PP2_SUBTYPE_SSL_VERSION);
		assert.match(version!.value.toString(), /^TLSv1\.[23]$/);

		const certTlvs = header.tlvs.filter((t) => t.type === PP2_TYPE_CLIENT_CERT);
		assert.ok(certTlvs.length >= 1, 'client cert TLV missing');
		const expectedDer = new crypto.X509Certificate(clientCa.clientCert).raw;
		assert.deepEqual(certTlvs[0].value, expectedDer, 'leaf DER must match the client cert');
	});

	it('omits cert TLVs when no client cert is presented (optional mTLS)', async () => {
		const payload = Buffer.from('hello-nocert');
		const [response, capture] = await Promise.all([
			tlsRoundTrip({
				port: proxyPort,
				servername: 'optional.localhost',
				caCert: serverCert.cert,
				data: payload,
			}),
			upstream.nextConnection(),
		]);
		assert.deepEqual(response, payload);

		const ssl = capture.header.tlvs.find((t) => t.type === PP2_TYPE_SSL);
		assert.ok(ssl, 'SSL TLV missing');
		assert.equal(ssl.value[0] & PP2_CLIENT_SSL, PP2_CLIENT_SSL);
		assert.equal(ssl.value[0] & PP2_CLIENT_CERT_CONN, 0, 'cert bit must be clear');
		assert.equal(capture.header.tlvs.filter((t) => t.type === PP2_TYPE_CLIENT_CERT).length, 0);

		const alpnOrAuthority = capture.header.tlvs.find((t) => t.type === PP2_TYPE_AUTHORITY);
		assert.equal(alpnOrAuthority?.value.toString(), 'optional.localhost');
	});

	it('rejects the handshake when requireClientCert=true and no cert is presented', async () => {
		await assert.rejects(
			tlsRoundTrip({
				port: proxyPort,
				servername: 'localhost',
				caCert: serverCert.cert,
				data: 'nope',
			}),
		);
	});

	it('rejects a client cert signed by a different CA', async () => {
		const otherCa = generateClientCa(true);
		
		await assert.rejects(
			tlsRoundTrip({
				port: proxyPort,
				servername: 'localhost',
				caCert: serverCert.cert,
				clientCert: otherCa.clientCert,
				clientKey: otherCa.clientKey,
				data: 'nope',
			}),
		);
	});
});

describe('PP2 ALPN TLV with http2 route', () => {
	const serverCert = generateSelfSignedCert('localhost');
	let proxyPort: number;
	let upstream: Pp2CaptureServer;
	let proxy: SymphonyProxy;

	before(async () => {
		upstream = await startPp2CaptureServer();
		proxyPort = await getFreePort();
		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: upstream.port }],
					terminateTls: true,
					cert: { certChain: serverCert.cert, privateKey: serverCert.key },
					http2: true,
					sourceAddressHeader: 'proxyProtocolV2',
				},
			],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await upstream.close();
	});

	it('carries the negotiated ALPN protocol', async () => {
		const payload = Buffer.from('alpn-check');
		const [, capture] = await Promise.all([
			// Node negotiates http/1.1 from ['h2', 'http/1.1'] via ALPNProtocols on a raw TLS socket
			new Promise<void>((resolve, reject) => {
				const tls = require('node:tls');
				const socket = tls.connect(
					{
						port: proxyPort,
						host: '127.0.0.1',
						servername: 'localhost',
						ca: serverCert.cert,
						rejectUnauthorized: false,
						ALPNProtocols: ['http/1.1'],
					},
					() => socket.write(payload),
				);
				socket.on('data', () => socket.end());
				socket.on('end', resolve);
				socket.on('error', reject);
				setTimeout(() => reject(new Error('alpn roundtrip timeout')), 5000);
			}),
			upstream.nextConnection(),
		]);
		const alpn = capture.header.tlvs.find((t) => t.type === PP2_TYPE_ALPN);
		assert.equal(alpn?.value.toString(), 'http/1.1');
	});
});
