/**
 * Integration tests for ALPN-based upstream dispatch — a route with an
 * h2-marked UDS upstream sends ALPN-h2 connections there and everything
 * else to the unmarked (HTTP/1.x) upstream.
 *
 * These tests require the native addon to be built:
 *   npm run build:debug
 */

import assert from 'node:assert/strict';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import tls from 'node:tls';
import fs from 'node:fs';
import { after, before, describe, it } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import { generateSelfSignedCert, getFreePort, sleep } from './util.js';

/** UDS server that records the first data chunk of every connection and echoes a tag back. */
function startRecordingUds(tag: string): Promise<{ path: string; firstChunks: Buffer[]; close: () => Promise<void> }> {
	const sockPath = path.join(os.tmpdir(), `sym-h2d-${tag}-${process.pid}-${Math.random().toString(36).slice(2)}.sock`);
	const firstChunks: Buffer[] = [];
	const server = net.createServer((socket) => {
		socket.once('data', (chunk) => {
			firstChunks.push(chunk);
			socket.write(`tag:${tag}`);
		});
		socket.on('error', () => {});
	});
	return new Promise((resolve) => {
		server.listen(sockPath, () =>
			resolve({
				path: sockPath,
				firstChunks,
				close: () =>
					new Promise((r) => {
						server.close(() => {
							try {
								fs.unlinkSync(sockPath);
							} catch {}
							r(undefined);
						});
					}),
			})
		);
	});
}

/** TLS connect with the given ALPN offer; returns { alpn, reply } after writing `data`. */
function alpnRoundTrip(opts: {
	port: number;
	servername: string;
	alpn: string[];
	data: string;
}): Promise<{ alpn: string | false; reply: string }> {
	return new Promise((resolve, reject) => {
		const socket = tls.connect(
			{
				host: '127.0.0.1',
				port: opts.port,
				servername: opts.servername,
				ALPNProtocols: opts.alpn,
				rejectUnauthorized: false,
			},
			() => {
				socket.write(opts.data);
			}
		);
		let reply = '';
		socket.setEncoding('utf8');
		socket.on('data', (d) => {
			reply += d;
			socket.end();
		});
		socket.on('close', () => resolve({ alpn: socket.alpnProtocol ?? false, reply }));
		socket.on('error', reject);
		setTimeout(() => reject(new Error('alpnRoundTrip timeout')), 3000).unref();
	});
}

describe('SymphonyProxy – ALPN h2 upstream dispatch', () => {
	const cert = generateSelfSignedCert('localhost');
	let proxyPort: number;
	let h1Up: Awaited<ReturnType<typeof startRecordingUds>>;
	let h2Up: Awaited<ReturnType<typeof startRecordingUds>>;
	let proxy: SymphonyProxy;

	before(async () => {
		h1Up = await startRecordingUds('h1');
		h2Up = await startRecordingUds('h2');
		proxyPort = await getFreePort();

		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [
						{ kind: 'uds', path: h1Up.path },
						{ kind: 'uds', path: h2Up.path, protocol: 'h2' },
					],
					terminateTls: true,
					http2: true,
					sourceAddressHeader: 'proxyProtocol',
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await h1Up.close();
		await h2Up.close();
	});

	it('sends an ALPN-h2 connection to the h2-marked upstream, with PROXY v1 first', async () => {
		const { alpn, reply } = await alpnRoundTrip({
			port: proxyPort,
			servername: 'localhost',
			alpn: ['h2', 'http/1.1'],
			data: 'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n',
		});
		assert.equal(alpn, 'h2');
		assert.equal(reply, 'tag:h2');
		assert.equal(h2Up.firstChunks.length, 1);
		const first = h2Up.firstChunks[0].toString('latin1');
		assert.match(first, /^PROXY TCP4 127\.0\.0\.1 /);
		assert.ok(first.includes('PRI * HTTP/2.0'), 'h2 preface should follow the PROXY header');
	});

	it('sends an http/1.1 connection to the unmarked upstream', async () => {
		const { alpn, reply } = await alpnRoundTrip({
			port: proxyPort,
			servername: 'localhost',
			alpn: ['http/1.1'],
			data: 'GET / HTTP/1.1\r\nHost: localhost\r\n\r\n',
		});
		assert.equal(alpn, 'http/1.1');
		assert.equal(reply, 'tag:h1');
		assert.equal(h1Up.firstChunks.length, 1);
		assert.match(h1Up.firstChunks[0].toString('latin1'), /^PROXY TCP4 /);
	});
});

describe('SymphonyProxy – h2 upstream config validation', () => {
	const cert = generateSelfSignedCert('localhost');

	it('rejects xForwardedFor combined with h2 upstreams (route dropped)', async () => {
		const up = await startRecordingUds('xff');
		const proxyPort = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [
						{ kind: 'uds', path: up.path },
						{ kind: 'uds', path: up.path, protocol: 'h2' },
					],
					terminateTls: true,
					http2: true,
					sourceAddressHeader: 'xForwardedFor',
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
		await proxy.start();
		await sleep(50);
		// The invalid route is isolated and dropped: the SNI resolves to nothing.
		await assert.rejects(
			alpnRoundTrip({ port: proxyPort, servername: 'localhost', alpn: ['http/1.1'], data: 'x' }),
			/timeout|ECONNRESET|EPROTO|socket hang up|closed/i
		);
		await proxy.stop();
		await up.close();
	});

	it('rejects a route whose upstreams are all h2-marked', async () => {
		const up = await startRecordingUds('allh2');
		const proxyPort = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'uds', path: up.path, protocol: 'h2' }],
					terminateTls: true,
					http2: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
		await proxy.start();
		await sleep(50);
		await assert.rejects(
			alpnRoundTrip({ port: proxyPort, servername: 'localhost', alpn: ['h2', 'http/1.1'], data: 'x' }),
			/timeout|ECONNRESET|EPROTO|socket hang up|closed/i
		);
		await proxy.stop();
		await up.close();
	});

	// Note: `protocol` on a tcp upstream is rejected at the napi layer, but the typed
	// SymphonyProxy wrapper cannot produce it (TcpUpstream has no such field and
	// toJsUpstream doesn't forward it), so that guard is unreachable via the public API.
});
