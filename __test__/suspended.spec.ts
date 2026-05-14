/**
 * Tests for suspended routes: hold → resolveConnection → proxy, and timeout → drop.
 *
 * IMPORTANT: For suspended routes, the TLS handshake happens AFTER resolveConnection()
 * is called. The connection flow is:
 *   TCP connect → peek → route lookup → suspended (emit event, wait) →
 *   resolveConnection() → TLS handshake → proxy to upstream
 *
 * Tests must therefore NOT wait for secureConnect before calling resolveConnection.
 * Instead: initiate the raw TCP/TLS connect, wait for the 'suspended' event,
 * call resolveConnection, THEN wait for secureConnect.
 */

import assert from 'node:assert/strict';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { after, before, describe, it } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import type { SuspendedConnection } from '../ts/types.js';
import { generateSelfSignedCert, getFreePort, startEchoServer, sleep } from './util.js';

/**
 * Open a TLS connection. Returns the socket (NOT awaiting secureConnect,
 * since the handshake may be deferred until after resolveConnection).
 */
function startTlsSocket(port: number, servername: string, ca: string): tls.TLSSocket {
	return tls.connect({ port, host: '127.0.0.1', servername, ca, rejectUnauthorized: false });
}

/** Wait for secureConnect or error/close — whichever comes first. */
function waitForSecureConnect(socket: tls.TLSSocket, timeoutMs = 5000): Promise<void> {
	return new Promise((resolve, reject) => {
		if (socket.authorized || (socket as any).encrypted) {
			resolve();
			return;
		}
		socket.once('secureConnect', resolve);
		socket.once('error', reject);
		socket.once('close', () => reject(new Error('socket closed before secureConnect')));
		setTimeout(() => reject(new Error('secureConnect timeout')), timeoutMs);
	});
}

/** Wait for socket to close (destroyed or ended). */
function waitForClose(socket: tls.TLSSocket | net.Socket, timeoutMs = 3000): Promise<void> {
	return new Promise((resolve) => {
		if (socket.destroyed) { resolve(); return; }
		socket.once('close', resolve);
		socket.once('error', resolve);
		setTimeout(resolve, timeoutMs);
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
		await echo.close();
	});

	it('emits suspended event and holds the connection, then proxies after resolve', async () => {
		// 1. Initiate TLS connection — do NOT await secureConnect yet.
		//    The handshake will only complete after resolveConnection().
		const socket = startTlsSocket(proxyPort, 'localhost', cert.cert);

		// 2. Wait for the proxy to peek the ClientHello and emit 'suspended'
		await sleep(200);
		assert.ok(capturedConn !== null, 'expected suspended event to have fired');
		assert.equal(capturedConn!.sni, 'localhost');
		assert.ok(capturedConn!.id, 'expected non-empty id');
		assert.ok(capturedConn!.peerIp, 'expected non-empty peerIp');
		assert.ok(capturedConn!.listener, 'expected non-empty listener');

		// 3. Resolve the connection — this triggers the TLS handshake + proxying.
		//    terminateTls: true = proxy terminates TLS from the client, then forwards
		//    plaintext to the upstream. The cert must be provided here because the
		//    resolved route builds its own TLS config (the original route's config
		//    is not reused for resolved connections).
		proxy.resolveConnection(capturedConn!.id, {
			upstream: { kind: 'tcp', host: '127.0.0.1', port: echo.port },
			terminateTls: true,
			cert: { certChain: cert.cert, privateKey: cert.key },
		});

		// 4. Now the TLS handshake should complete
		await waitForSecureConnect(socket);

		// 5. Send data and expect it echoed back
		const payload = Buffer.from('suspended-resolved');
		socket.write(payload);

		const response = await new Promise<Buffer>((resolve, reject) => {
			const chunks: Buffer[] = [];
			socket.on('data', (chunk: Buffer) => {
				chunks.push(chunk);
				if (Buffer.concat(chunks).length >= payload.length) {
					resolve(Buffer.concat(chunks));
				}
			});
			socket.on('error', reject);
			setTimeout(() => reject(new Error('data timeout after resolve')), 5000);
		});

		assert.deepEqual(response, payload);
		socket.end();
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
		// Initiate the TCP connection. The TLS handshake won't happen (no resolve).
		const socket = startTlsSocket(proxyPort, 'localhost', cert.cert);

		// Wait longer than suspendTimeoutMs (200ms) for the proxy to drop it.
		await waitForClose(socket, 2000);

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
		// Initiate the connection (no secureConnect expected)
		const socket = startTlsSocket(proxyPort, 'localhost', cert.cert);
		await sleep(200);

		assert.ok(capturedConn !== null, 'expected suspended event to have fired');

		// Reject the connection
		proxy.resolveConnection(capturedConn!.id, null);

		// Socket should close shortly after
		await waitForClose(socket, 2000);
		assert.ok(socket.destroyed || !socket.writable, 'socket should be closed after rejection');
	});
});
