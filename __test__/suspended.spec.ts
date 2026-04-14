/**
 * Tests for suspended routes: hold → resolveConnection → proxy, and timeout → drop.
 */

import assert from 'node:assert/strict';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { after, before, describe, it } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import type { SuspendedConnection } from '../ts/types.js';
import { generateSelfSignedCert, getFreePort, startEchoServer, sleep } from './util.js';

/** Open a TLS connection to the proxy without sending data, returns socket + close fn. */
function openTlsSocket(port: number, servername: string, ca: string): Promise<tls.TLSSocket> {
	return new Promise((resolve, reject) => {
		const socket = tls.connect({ port, host: '127.0.0.1', servername, ca, rejectUnauthorized: false });
		socket.on('secureConnect', () => resolve(socket));
		socket.on('error', reject);
		setTimeout(() => reject(new Error('openTlsSocket timeout')), 3000);
	});
}

describe('Suspended routes – hold then resolve', () => {
	const cert = generateSelfSignedCert('localhost');
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;
	let capturedConn: SuspendedConnection | null = null;

	before(async () => {
		echo = await startEchoServer();
		proxyPort = await getFreePort();

		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [], // ignored while suspended
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
					suspended: true,
					suspendTimeoutMs: 2000,
				},
			],
		});

		proxy.on('suspended', (conn) => {
			capturedConn = conn;
		});

		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await echo.close();
	});

	it('emits suspended event and holds the connection', async () => {
		const socket = await openTlsSocket(proxyPort, 'localhost', cert.cert);
		await sleep(100);

		assert.ok(capturedConn !== null, 'expected suspended event to have fired');
		assert.equal(capturedConn!.sni, 'localhost');
		assert.ok(capturedConn!.id, 'expected non-empty id');
		assert.ok(capturedConn!.peerIp, 'expected non-empty peerIp');
		assert.ok(capturedConn!.listener, 'expected non-empty listener');

		// Resolve and proxy to the echo server
		proxy.resolveConnection(capturedConn!.id, {
			upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
			terminateTls: false, // upstream is plain TCP
		});

		// Now the socket should be connected — send data and expect echo
		await new Promise<void>((resolve, reject) => {
			const payload = Buffer.from('suspended-resolved');
			socket.write(payload);
			const chunks: Buffer[] = [];
			socket.on('data', (chunk: Buffer) => {
				chunks.push(chunk);
				if (Buffer.concat(chunks).length >= payload.length) {
					assert.deepEqual(Buffer.concat(chunks), payload);
					socket.end();
					resolve();
				}
			});
			socket.on('error', reject);
			setTimeout(() => reject(new Error('data timeout after resolve')), 3000);
		});
	});
});

describe('Suspended routes – timeout drops connection', () => {
	const cert = generateSelfSignedCert('localhost');
	let proxyPort: number;
	let proxy: SymphonyProxy;

	before(async () => {
		proxyPort = await getFreePort();

		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
					suspended: true,
					suspendTimeoutMs: 200, // short timeout for fast tests
				},
			],
		});

		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
	});

	it('drops the connection after suspend timeout', async () => {
		const socket = await openTlsSocket(proxyPort, 'localhost', cert.cert);

		// Don't call resolveConnection — wait for the timeout to drop the connection
		await new Promise<void>((resolve) => {
			socket.on('close', resolve);
			socket.on('end', resolve);
			socket.on('error', resolve);
			setTimeout(resolve, 1000); // safety: don't hang if socket stays open
		});

		assert.ok(socket.destroyed || !socket.writable, 'socket should be destroyed after timeout');
	});
});

describe('Suspended routes – reject with null', () => {
	const cert = generateSelfSignedCert('localhost');
	let proxyPort: number;
	let proxy: SymphonyProxy;
	let capturedConn: SuspendedConnection | null = null;

	before(async () => {
		proxyPort = await getFreePort();

		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
					suspended: true,
					suspendTimeoutMs: 5000,
				},
			],
		});

		proxy.on('suspended', (conn) => {
			capturedConn = conn;
		});

		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
	});

	it('closes connection when resolveConnection called with null', async () => {
		const socket = await openTlsSocket(proxyPort, 'localhost', cert.cert);
		await sleep(100);

		assert.ok(capturedConn !== null);

		// Reject the connection
		proxy.resolveConnection(capturedConn!.id, null);

		await new Promise<void>((resolve) => {
			socket.on('close', resolve);
			socket.on('end', resolve);
			socket.on('error', resolve);
			setTimeout(resolve, 2000);
		});

		assert.ok(socket.destroyed || !socket.writable, 'socket should be closed after rejection');
	});
});
