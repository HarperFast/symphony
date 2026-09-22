/**
 * Dead-peer detection (issue #45): the half-close bound and the keepalive config surface.
 *
 * Reaping a genuinely vanished peer is not covered here — that needs a peer whose packets stop
 * without a FIN or RST (an `iptables DROP` or a severed netns), which a single-host Node test
 * cannot produce. `src/liveness.rs` covers the configuration half of that mechanism instead.
 *
 * Requires the native addon to be built (npm run build:debug).
 */

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import * as net from 'node:net';
import { SymphonyProxy } from '../ts/index.js';
import type { ProxyConfig } from '../ts/types.js';
import { clientHello, getFreePort, sleep } from './util.js';

const HALF_CLOSE_MS = 300;
const SNI = 'liveness.test';

async function waitFor(predicate: () => boolean, timeoutMs = 5000, stepMs = 25): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (predicate()) return;
		await sleep(stepMs);
	}
	throw new Error('waitFor: timed out');
}

function reasonCount(reasons: Array<{ reason: string; count: number }>, reason: string): number {
	const match = reasons.find((r) => r.reason === reason);
	assert.ok(match, `expected a '${reason}' entry; got ${reasons.map((r) => r.reason).join(', ')}`);
	return match.count;
}

describe('dead connection reaping', () => {
	const running: SymphonyProxy[] = [];
	const servers: net.Server[] = [];
	/** Every socket either side opened, so teardown can drop the half-open ones. */
	const sockets: net.Socket[] = [];

	after(async () => {
		// Half-open sockets are the point of these tests, so nothing closes on its own —
		// close() alone would wait on them forever.
		for (const s of sockets) s.destroy();
		await Promise.all(running.map((p) => p.stop()));
		await Promise.all(servers.map((s) => new Promise((r) => s.close(() => r(undefined)))));
	});

	/** A passthrough proxy in front of `onConnection`, so a client FIN is a plain TCP FIN. */
	async function startProxy(
		onConnection: (socket: net.Socket) => void,
		overrides: Partial<ProxyConfig> = {}
	): Promise<{ proxy: SymphonyProxy; port: number }> {
		// allowHalfOpen so the upstream models a server that keeps working after the client
		// half-closes; Node's default would answer that FIN with its own and end the response.
		const upstream = net.createServer({ allowHalfOpen: true }, (socket) => {
			sockets.push(socket);
			onConnection(socket);
		});
		servers.push(upstream);
		const upstreamPort = await getFreePort();
		await new Promise<void>((r) => upstream.listen(upstreamPort, '127.0.0.1', r));

		const port = await getFreePort();
		const proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port }],
			routes: [
				{ sni: SNI, upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: upstreamPort }], terminateTls: false },
			],
			halfCloseTimeoutMs: HALF_CLOSE_MS,
			...overrides,
		});
		await proxy.start();
		running.push(proxy);
		await sleep(50);
		return { proxy, port };
	}

	/**
	 * Connect and send the ClientHello. It is not optional: `sni::peek` blocks up to its 5s
	 * reassembly timeout waiting for one, and a connection with no SNI resolves to no route at
	 * all — so without it the connection never reaches the copy phase these tests are about.
	 */
	function connect(port: number): Promise<net.Socket> {
		return new Promise((resolve) => {
			// allowHalfOpen is what makes this client the peer from the issue: without it Node
			// answers the proxy's FIN with its own, and the connection closes on its own.
			const socket = net.createConnection({ host: '127.0.0.1', port, allowHalfOpen: true });
			socket.on('error', () => {});
			sockets.push(socket);
			socket.on('connect', () => {
				socket.write(clientHello(SNI));
				resolve(socket);
			});
		});
	}

	it('reclaims a connection whose upstream closed and whose client never sends a FIN', async () => {
		const { proxy, port } = await startProxy((socket) => socket.end());
		const client = await connect(port);
		client.resume(); // read the upstream's FIN, then hold the socket open and stay silent

		await waitFor(() => proxy.metrics().listeners[0].activeConnections === 0);
		const listener = proxy.metrics().listeners[0];
		assert.equal(reasonCount(listener.errorsByReason, 'half_closed'), 1);
		assert.equal(listener.halfClosedConnections, 0, 'the gauge comes back down when the connection ends');
		client.destroy();
	});

	it('counts a half-closed connection in the gauge while it is being held', async () => {
		// A window long enough to observe the gauge before the bound reclaims the connection.
		const { proxy, port } = await startProxy((socket) => socket.end(), { halfCloseTimeoutMs: 5000 });
		const client = await connect(port);
		client.resume();

		await waitFor(() => proxy.metrics().listeners[0].halfClosedConnections === 1);
		assert.equal(proxy.metrics().listeners[0].activeConnections, 1);

		client.destroy();
		await waitFor(() => proxy.metrics().listeners[0].halfClosedConnections === 0);
	});

	// The shape the bound must not touch: the client has shut down its write half and the
	// response's first byte comes well after the window would have expired.
	it('does not truncate a slow response after the client half-closes', async () => {
		const { proxy, port } = await startProxy((socket) => {
			socket.resume();
			setTimeout(() => socket.end('late'), HALF_CLOSE_MS * 4);
		});
		const client = await connect(port);
		client.end('request');

		const body = await new Promise<Buffer>((resolve) => {
			const chunks: Buffer[] = [];
			client.on('data', (c) => chunks.push(c));
			client.on('end', () => resolve(Buffer.concat(chunks)));
		});
		assert.equal(body.toString(), 'late');
		assert.equal(reasonCount(proxy.metrics().listeners[0].errorsByReason, 'half_closed'), 0);
	});

	it('holds a half-closed connection open while the surviving direction is still carrying bytes', async () => {
		let received = 0;
		const { proxy, port } = await startProxy((socket) => {
			socket.on('data', (c) => (received += c.length));
			socket.end();
		});
		const client = await connect(port);
		client.resume();

		for (let i = 0; i < 8; i++) {
			client.write('x');
			await sleep(HALF_CLOSE_MS / 3);
		}
		// 800ms of dripping bytes, well past a 300ms window that did not reset.
		assert.equal(proxy.metrics().listeners[0].activeConnections, 1, 'activity must defer the bound');
		assert.ok(received > 0);

		client.destroy();
		await waitFor(() => proxy.metrics().listeners[0].activeConnections === 0);
	});

	it('holds the connection indefinitely when the bound is disabled', async () => {
		const { proxy, port } = await startProxy((socket) => socket.end(), { halfCloseTimeoutMs: 0 });
		const client = await connect(port);
		client.resume();

		await waitFor(() => proxy.metrics().listeners[0].halfClosedConnections === 1);
		await sleep(HALF_CLOSE_MS * 4);
		assert.equal(proxy.metrics().listeners[0].activeConnections, 1, 'halfCloseTimeoutMs: 0 disables the bound');
		client.destroy();
	});

	it('rejects a keepalive schedule that cannot be honoured', async () => {
		const port = await getFreePort();
		const config = (tcpKeepalive: ProxyConfig['tcpKeepalive']): ProxyConfig => ({
			listeners: [{ host: '127.0.0.1', port }],
			routes: [{ sni: SNI, upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: 1 }], terminateTls: false }],
			tcpKeepalive,
		});
		assert.throws(() => new SymphonyProxy(config({ idleMs: 0 })), /idleMs must be a number of ms/);
		assert.throws(() => new SymphonyProxy(config({ intervalMs: -1 })), /intervalMs must be a number of ms/);
		assert.throws(() => new SymphonyProxy(config({ retries: 0 })), /retries must be in \[1, 127\]/);
		assert.throws(() => new SymphonyProxy(config({ retries: 128 })), /retries must be in \[1, 127\]/);
		// Sub-second timings reach the kernel as whole seconds, so they would install as 0 and be
		// rejected by setsockopt long after construction reported success.
		assert.throws(() => new SymphonyProxy(config({ idleMs: 500 })), /idleMs must be a number of ms/);
		assert.throws(() => new SymphonyProxy(config({ intervalMs: 999 })), /intervalMs must be a number of ms/);
		assert.throws(
			() => new SymphonyProxy({ ...config(undefined), halfCloseTimeoutMs: Number.NaN }),
			/halfCloseTimeoutMs must be a number of ms/
		);
		// 0.5 would truncate to Duration::ZERO and silently disable the bound; 0 is the documented
		// way to do that on purpose.
		assert.throws(
			() => new SymphonyProxy({ ...config(undefined), halfCloseTimeoutMs: 0.5 }),
			/halfCloseTimeoutMs must be a number of ms/
		);
		assert.doesNotThrow(() => new SymphonyProxy({ ...config(undefined), halfCloseTimeoutMs: 0 }));
		// `enabled: false` is the supported way to turn it off, and it is not an error.
		assert.doesNotThrow(() => new SymphonyProxy(config({ enabled: false })));
	});
});
