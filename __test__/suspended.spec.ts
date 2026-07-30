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

describe('Suspended routes – resolveConnection() with an invalid route never throws', () => {
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

		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
	});

	// resolveConnection() is meant to be called synchronously — or, per the documented usage,
	// from an *async* 'suspended' listener — and either way there is no safe way for a config-
	// validation failure (issue #38's protocol/carrier checks, also applied to resolveConnection)
	// to reach the caller as a thrown exception: EventEmitter.emit() never awaits an async
	// listener, so a throw after an `await` becomes an unhandled rejection regardless of any
	// guard around `emit()`, and even a synchronous throw only reaches user code safely if an
	// 'error' listener happens to be attached. So resolveConnection() itself never throws for a
	// validation failure (src/proxy.rs) — it drops the connection exactly as
	// resolveConnection(id, null) would (closing this test's socket promptly, not leaking it for
	// the full suspendTimeoutMs) and surfaces the reason via the existing 'error' event, the same
	// channel every other native-originated error already uses.
	it('drops the connection and emits "error" — without throwing — when resolveConnection() is given an invalid route', async () => {
		const errors: Error[] = [];
		// .once, not .on: this describe block runs more than one test against the same shared
		// `proxy`, and a listener left attached from an earlier test would fire again here too,
		// double-counting errors (or, for 'suspended', calling resolveConnection twice for the
		// same connection).
		proxy.once('error', (err: Error) => errors.push(err));
		proxy.once('suspended', (conn) => {
			capturedConn = conn;
			// Undeclared xForwardedFor — rejected by parse_resolve_spec's protocol-declaration check.
			assert.doesNotThrow(() =>
				proxy.resolveConnection(conn.id, {
					upstream: { kind: 'tcp', host: '127.0.0.1', port: 1 },
					terminateTls: true,
					sourceAddressHeader: 'xForwardedFor',
				})
			);
		});

		const socket = startTlsSocket(proxyPort, 'localhost', cert.cert);
		// The connection is dropped as soon as resolveConnection() runs inside the 'suspended'
		// listener above — i.e. before this test body reaches waitForClose() below — so the error
		// listener must be attached up front, not only once we get around to waiting for it.
		socket.on('error', () => {});
		await sleep(200);

		assert.ok(capturedConn !== null, 'expected suspended event to have fired');
		assert.equal(errors.length, 1, 'the validation failure must surface as exactly one "error" event');
		assert.match(errors[0].message, /protocol/i, 'the surfaced error must be the protocol-declaration rejection');

		// The connection must be dropped promptly (like resolveConnection(id, null)), not held open
		// for the full 5s suspendTimeoutMs — that hold-open-until-timeout was the resource-retention
		// half of the bug this fix closes.
		await waitForClose(socket, 2000);
		assert.ok(socket.destroyed || !socket.writable, 'socket must close promptly, not linger until suspendTimeoutMs');

		socket.destroy();
	});

	// The README documents `proxy.on('suspended', async (conn) => { ... })`. EventEmitter.emit()
	// does not await an async listener, so a throw after an `await` would become an
	// unhandledRejection no ts/proxy.ts-level try/catch around emit() could ever intercept — the
	// only robust fix is the one under test above: resolveConnection() itself must not throw. This
	// test pins that the async-listener shape is safe too, not just the synchronous one.
	it('is also safe from an async "suspended" listener (the documented usage)', async () => {
		const errors: Error[] = [];
		const unhandledRejections: unknown[] = [];
		const onUnhandledRejection = (reason: unknown) => unhandledRejections.push(reason);
		process.on('unhandledRejection', onUnhandledRejection);

		proxy.once('error', (err: Error) => errors.push(err));
		proxy.once('suspended', async (conn) => {
			capturedConn = conn;
			await sleep(10); // simulate an async lookup before resolving, per the documented pattern
			proxy.resolveConnection(conn.id, {
				upstream: { kind: 'tcp', host: '127.0.0.1', port: 1 },
				terminateTls: true,
				sourceAddressHeader: 'xForwardedFor',
			});
		});

		const socket = startTlsSocket(proxyPort, 'localhost', cert.cert);
		socket.on('error', () => {}); // the connection is dropped once resolveConnection() runs above
		await sleep(300);

		process.off('unhandledRejection', onUnhandledRejection);

		assert.ok(capturedConn !== null, 'expected suspended event to have fired');
		assert.equal(unhandledRejections.length, 0, 'an async listener rejecting after resolveConnection() must not produce an unhandledRejection');
		assert.equal(errors.length, 1, 'the validation failure must still surface as exactly one "error" event');
		assert.match(errors[0].message, /protocol/i, 'the surfaced error must be the protocol-declaration rejection');

		socket.destroy();
	});
});
