/**
 * Peer failover across several symphony instances in one process. Each node has a public listener
 * and a `failoverIngress` listener, and its route's upstream is a Unix socket that may be absent.
 *
 * The client connects from 127.0.0.2 (loopback on Linux) so the address the serving node's
 * upstream sees can be told apart from the forwarding node's own 127.0.0.1.
 */

import assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import * as tls from 'node:tls';
import { after, describe, it, type TestContext } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import type { FailoverConfig, MtlsConfig, ProtectionConfig, RouteConfig } from '../ts/types.js';
import { generateClientCa, generateSelfSignedCert, getFreePort, sleep } from './util.js';

const SNI = 'app.test';
const CLIENT_ADDRESS = '127.0.0.2';
const { cert, key } = generateSelfSignedCert(SNI);
const socketDir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-failover-'));
let socketSeq = 0;

after(() => fs.rmSync(socketDir, { recursive: true, force: true }));

interface UdsUpstream {
	/** Client addresses from the PROXY v1 header of each request served. */
	sources: string[];
	close(): Promise<void>;
}

/** Echo server on a Unix socket that records the PROXY v1 source address it was given. */
function startUdsUpstream(socketPath: string): Promise<UdsUpstream> {
	return new Promise((resolve, reject) => {
		const sources: string[] = [];
		const sockets = new Set<net.Socket>();
		const server = net.createServer((socket) => {
			sockets.add(socket);
			socket.on('close', () => sockets.delete(socket));
			socket.on('error', () => {});
			let pending: Buffer | null = Buffer.alloc(0);
			socket.on('data', (chunk: Buffer) => {
				if (pending === null) {
					socket.write(chunk);
					return;
				}
				pending = Buffer.concat([pending, chunk]);
				const end = pending.indexOf('\r\n');
				if (end < 0) return;
				sources.push(pending.subarray(0, end).toString().split(' ')[2]);
				const rest = pending.subarray(end + 2);
				pending = null;
				if (rest.length > 0) socket.write(rest);
			});
		});
		server.listen(socketPath, () =>
			resolve({
				sources,
				close: () =>
					new Promise((res) => {
						for (const s of sockets) s.destroy();
						server.close(() => res());
					}),
			})
		);
		server.on('error', reject);
	});
}

interface NodeOptions {
	peers?: number[];
	drain?: boolean;
	mtls?: MtlsConfig;
	trustedSources?: string[];
	allowedSources?: string[];
	ingressProtection?: ProtectionConfig;
	/** Replaces the node's routes entirely (the failover route is not added). */
	routes?: RouteConfig[];
}

interface Node {
	publicPort: number;
	ingressPort: number;
	socketPath: string;
	proxy: SymphonyProxy;
	failoverRoute(overrides?: Partial<FailoverConfig>): RouteConfig;
}

async function allocatePorts(count: number): Promise<{ publicPort: number; ingressPort: number }[]> {
	const ports = [];
	for (let i = 0; i < count; i++) ports.push({ publicPort: await getFreePort(), ingressPort: await getFreePort() });
	return ports;
}

async function startNode(
	t: TestContext,
	ports: { publicPort: number; ingressPort: number },
	opts: NodeOptions = {}
): Promise<Node> {
	const socketPath = path.join(socketDir, `node-${++socketSeq}.sock`);
	const failoverRoute = (overrides: Partial<FailoverConfig> = {}): RouteConfig => ({
		sni: SNI,
		upstreams: [{ kind: 'uds', path: socketPath }],
		terminateTls: true,
		cert: { certChain: cert, privateKey: key },
		mtls: opts.mtls,
		allowedSources: opts.allowedSources,
		failover: opts.peers
			? {
					peers: opts.peers.map((port) => ({ host: '127.0.0.1', port })),
					drain: opts.drain,
					probeIntervalMs: 50,
					peerCooldownMs: { min: 200, max: 1000 },
					...overrides,
				}
			: undefined,
	});
	const proxy = new SymphonyProxy({
		workerThreads: 1,
		listeners: [
			{ host: '127.0.0.1', port: ports.publicPort },
			{
				host: '127.0.0.1',
				port: ports.ingressPort,
				failoverIngress: { trustedSources: opts.trustedSources ?? ['127.0.0.1/32'] },
				protection: opts.ingressProtection,
			},
		],
		routes: opts.routes ?? [failoverRoute()],
	});
	await proxy.start();
	t.after(() => proxy.stop());
	return { ...ports, socketPath, proxy, failoverRoute };
}

/** The echoed reply, or null when the connection failed or closed without echoing. */
function tryEcho(opts: {
	port: number;
	clientCert?: string;
	clientKey?: string;
	socket?: net.Socket;
}): Promise<string | null> {
	return new Promise((resolve) => {
		const payload = 'ping';
		let reply = '';
		const socket = tls.connect({
			socket: opts.socket ?? net.connect({ host: '127.0.0.1', port: opts.port, localAddress: CLIENT_ADDRESS }),
			servername: SNI,
			rejectUnauthorized: false,
			cert: opts.clientCert,
			key: opts.clientKey,
		});
		const timer = setTimeout(() => finish(null), 5000);
		const finish = (value: string | null) => {
			clearTimeout(timer);
			socket.destroy();
			resolve(value);
		};
		socket.on('secureConnect', () => socket.write(payload));
		socket.on('data', (chunk: Buffer) => {
			reply += chunk.toString();
			if (reply.length >= payload.length) finish(reply);
		});
		socket.on('error', () => finish(null));
		socket.on('close', () => finish(reply || null));
	});
}

function routeHealth(proxy: SymphonyProxy, status: 'up' | 'down'): Promise<void> {
	return new Promise((resolve) => {
		const listener = (event: { status: string }) => {
			if (event.status === status) {
				proxy.off('routeHealth', listener);
				resolve();
			}
		};
		proxy.on('routeHealth', listener);
	});
}

/**
 * Lose one connection to the absent local upstream, which is how a route learns it is down (the
 * race window the design accepts), and wait for the probe to report it.
 */
async function markDown(node: Node): Promise<void> {
	const down = routeHealth(node.proxy, 'down');
	assert.equal(await tryEcho({ port: node.publicPort }), null, 'the first connection to a dead upstream is lost');
	await down;
}

function routeMetrics(node: Node) {
	const route = node.proxy.metrics().routeMetrics.find((r) => r.route === SNI);
	assert.ok(route, 'route metrics present');
	return route;
}

function count(list: { reason: string; count: number }[], reason: string): number {
	return list.find((c) => c.reason === reason)?.count ?? 0;
}

function proxyV2Header(source: string, sourcePort: number): Buffer {
	const header = Buffer.alloc(28);
	Buffer.from('0d0a0d0a000d0a515549540a', 'hex').copy(header, 0);
	header[12] = 0x21;
	header[13] = 0x11;
	header.writeUInt16BE(12, 14);
	Buffer.from(source.split('.').map(Number)).copy(header, 16);
	Buffer.from([127, 0, 0, 1]).copy(header, 20);
	header.writeUInt16BE(sourcePort, 24);
	header.writeUInt16BE(443, 26);
	return header;
}

function connectRaw(port: number): Promise<net.Socket> {
	return new Promise((resolve, reject) => {
		const socket = net.connect({ host: '127.0.0.1', port }, () => resolve(socket));
		socket.on('error', reject);
	});
}

describe('peer failover', () => {
	it('forwards to a peer while the local upstream is absent, and the peer sees the real client', async (t) => {
		const [a, b] = await allocatePorts(2);
		const nodeA = await startNode(t, a, { peers: [b.ingressPort] });
		const nodeB = await startNode(t, b, { peers: [a.ingressPort] });
		const upstreamB = await startUdsUpstream(nodeB.socketPath);
		t.after(() => upstreamB.close());

		await markDown(nodeA);
		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.deepEqual(upstreamB.sources, [CLIENT_ADDRESS]);

		const failover = routeMetrics(nodeA).failover!;
		assert.equal(failover.localUp, false);
		assert.equal(failover.refusingSlots, 1);
		assert.equal(failover.peers[0].forwarded, 1);
	});

	it('returns new connections to the local upstream once the probe sees it back', async (t) => {
		const [a, b] = await allocatePorts(2);
		const nodeA = await startNode(t, a, { peers: [b.ingressPort] });
		const nodeB = await startNode(t, b, { peers: [a.ingressPort] });
		const upstreamB = await startUdsUpstream(nodeB.socketPath);
		t.after(() => upstreamB.close());
		await markDown(nodeA);

		const up = routeHealth(nodeA.proxy, 'up');
		const upstreamA = await startUdsUpstream(nodeA.socketPath);
		t.after(() => upstreamA.close());
		await up;
		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(upstreamA.sources.length, 1, 'served locally');
		assert.equal(upstreamB.sources.length, 0);
		assert.equal(routeMetrics(nodeA).failover!.localUp, true);
	});

	it('drain forwards while the local upstream is up', async (t) => {
		const [a, b] = await allocatePorts(2);
		const nodeA = await startNode(t, a, { peers: [b.ingressPort], drain: true });
		const nodeB = await startNode(t, b, { peers: [a.ingressPort] });
		const upstreamA = await startUdsUpstream(nodeA.socketPath);
		const upstreamB = await startUdsUpstream(nodeB.socketPath);
		t.after(() => upstreamA.close());
		t.after(() => upstreamB.close());

		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(upstreamA.sources.length, 0);
		assert.equal(upstreamB.sources.length, 1);
	});

	it('a peer that refuses the TCP connection is skipped for the next one', async (t) => {
		const [a, c] = await allocatePorts(2);
		const deadPort = await getFreePort();
		const nodeA = await startNode(t, a, { peers: [deadPort, c.ingressPort] });
		const nodeC = await startNode(t, c, { peers: [a.ingressPort] });
		const upstreamC = await startUdsUpstream(nodeC.socketPath);
		t.after(() => upstreamC.close());
		await markDown(nodeA);

		// Round-robin starts each connection at a different peer, so one of the two begins at the dead one.
		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(upstreamC.sources.length, 2);
		const [dead, live] = routeMetrics(nodeA).failover!.peers;
		assert.equal(count(dead.failuresByReason, 'refused'), 1);
		assert.equal(dead.coolingDown, true);
		assert.equal(live.forwarded, 2);
	});

	it('a peer whose own upstream is down closes with no bytes and the hello is replayed to the next', async (t) => {
		const [a, b, c] = await allocatePorts(3);
		const nodeA = await startNode(t, a, { peers: [b.ingressPort, c.ingressPort] });
		const nodeB = await startNode(t, b, { peers: [a.ingressPort] });
		const nodeC = await startNode(t, c, { peers: [a.ingressPort] });
		const upstreamC = await startUdsUpstream(nodeC.socketPath);
		t.after(() => upstreamC.close());
		await markDown(nodeA);
		await markDown(nodeB);

		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(upstreamC.sources.length, 2);
		const failover = routeMetrics(nodeA).failover!;
		assert.equal(count(failover.peers[0].failuresByReason, 'zero_byte_close'), 1);
		assert.equal(failover.replays, 1);
		assert.equal(count(routeMetrics(nodeB).errorsByReason, 'locally_down'), 1);
	});

	it('a peer with no route for the name closes before the handshake instead of using its catch-all', async (t) => {
		const [a, b, c] = await allocatePorts(3);
		const nodeA = await startNode(t, a, { peers: [b.ingressPort, c.ingressPort] });
		const otherSocket = path.join(socketDir, `other-${++socketSeq}.sock`);
		const otherUpstream = await startUdsUpstream(otherSocket);
		t.after(() => otherUpstream.close());
		const nodeB = await startNode(t, b, {
			routes: [
				{
					sni: '',
					upstreams: [{ kind: 'uds', path: otherSocket }],
					terminateTls: true,
					cert: { certChain: cert, privateKey: key },
				},
			],
		});
		const nodeC = await startNode(t, c, { peers: [a.ingressPort] });
		const upstreamC = await startUdsUpstream(nodeC.socketPath);
		t.after(() => upstreamC.close());
		await markDown(nodeA);
		assert.equal(await tryEcho({ port: b.publicPort }), 'ping');
		assert.equal(otherUpstream.sources.length, 1);

		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(upstreamC.sources.length, 2);
		assert.equal(otherUpstream.sources.length, 1);
		const ingressB = nodeB.proxy.metrics().listeners.find((l) => l.address === `127.0.0.1:${b.ingressPort}`)!;
		assert.equal(count(ingressB.errorsByReason, 'no_route'), 1);
	});

	it('closes the client when every node is down, without forwarding twice', async (t) => {
		const [a, b, c] = await allocatePorts(3);
		const nodeA = await startNode(t, a, { peers: [b.ingressPort, c.ingressPort] });
		const nodeB = await startNode(t, b, { peers: [a.ingressPort, c.ingressPort] });
		const nodeC = await startNode(t, c, { peers: [a.ingressPort, b.ingressPort] });
		await markDown(nodeA);
		await markDown(nodeB);
		await markDown(nodeC);

		assert.equal(await tryEcho({ port: a.publicPort }), null);
		assert.equal(routeMetrics(nodeA).failover!.exhausted, 1);
		for (const peer of [nodeB, nodeC]) {
			const route = routeMetrics(peer);
			assert.equal(count(route.errorsByReason, 'locally_down'), 1);
			assert.ok(
				route.failover!.peers.every((p) => p.forwarded === 0 && count(p.failuresByReason, 'zero_byte_close') === 0),
				'an ingress connection is never forwarded on'
			);
		}
	});

	it('the peer verifies the client certificate of a forwarded mTLS connection', async (t) => {
		const ca = generateClientCa();
		const [a, b] = await allocatePorts(2);
		// The forwarding node has no client-cert policy at all; any check must be the peer's.
		const nodeA = await startNode(t, a, { peers: [b.ingressPort] });
		const nodeB = await startNode(t, b, {
			peers: [a.ingressPort],
			mtls: { clientCaCert: ca.caCert, requireClientCert: true },
		});
		const upstreamB = await startUdsUpstream(nodeB.socketPath);
		t.after(() => upstreamB.close());
		await markDown(nodeA);

		assert.equal(await tryEcho({ port: a.publicPort }), null, 'no client cert');
		assert.equal(await tryEcho({ port: a.publicPort, clientCert: ca.clientCert, clientKey: ca.clientKey }), 'ping');
		assert.equal(upstreamB.sources.length, 1);
	});

	it('closes a connection whose local upstream dies mid-stream instead of forwarding it', async (t) => {
		const [a, b] = await allocatePorts(2);
		const nodeA = await startNode(t, a, { peers: [b.ingressPort] });
		const nodeB = await startNode(t, b, { peers: [a.ingressPort] });
		const upstreamA = await startUdsUpstream(nodeA.socketPath);
		const upstreamB = await startUdsUpstream(nodeB.socketPath);
		t.after(() => upstreamB.close());

		const closed = new Promise<string>((resolve) => {
			const socket = tls.connect({ host: '127.0.0.1', port: a.publicPort, servername: SNI, rejectUnauthorized: false });
			socket.on('secureConnect', () => socket.write('ping'));
			socket.once('data', () => void upstreamA.close());
			socket.on('error', () => {});
			socket.on('close', () => resolve('closed'));
			setTimeout(() => {
				socket.destroy();
				resolve('still open');
			}, 5000).unref();
		});
		assert.equal(await closed, 'closed');
		assert.equal(upstreamB.sources.length, 0);
	});
});

describe('failover ingress', () => {
	it('closes an untrusted source before reading, and trustedSources hot-swaps', async (t) => {
		const [b] = await allocatePorts(1);
		const nodeB = await startNode(t, b, { trustedSources: ['10.0.0.0/8'] });
		const upstreamB = await startUdsUpstream(nodeB.socketPath);
		t.after(() => upstreamB.close());
		const ingress = () => nodeB.proxy.metrics().listeners.find((l) => l.address === `127.0.0.1:${b.ingressPort}`)!;

		const socket = await connectRaw(b.ingressPort);
		socket.write(proxyV2Header('198.51.100.7', 4000));
		assert.equal(await tryEcho({ port: b.ingressPort, socket }), null);
		assert.equal(count(ingress().blockedByReason, 'untrusted_source'), 1);

		nodeB.proxy.updateConfig({ failoverIngress: [{ port: b.ingressPort, trustedSources: ['127.0.0.1/32'] }] });
		const trusted = await connectRaw(b.ingressPort);
		trusted.write(proxyV2Header('198.51.100.7', 4000));
		assert.equal(await tryEcho({ port: b.ingressPort, socket: trusted }), 'ping');
		assert.deepEqual(upstreamB.sources, ['198.51.100.7']);

		assert.throws(
			() => nodeB.proxy.updateConfig({ failoverIngress: [{ port: b.publicPort, trustedSources: [] }] }),
			/without failoverIngress/
		);
	});

	it('rejects a connection without a PROXY v2 header', async (t) => {
		const [b] = await allocatePorts(1);
		const nodeB = await startNode(t, b);
		const socket = await connectRaw(b.ingressPort);
		socket.write('PROXY TCP4 198.51.100.7 127.0.0.1 4000 443\r\n');
		assert.equal(await tryEcho({ port: b.ingressPort, socket }), null);
		const ingress = nodeB.proxy.metrics().listeners.find((l) => l.address === `127.0.0.1:${b.ingressPort}`)!;
		assert.equal(count(ingress.blockedByReason, 'proxy_header_v1'), 1);
	});

	it('a trusted source can assert the client address that protection, allowedSources and the upstream use', async (t) => {
		const [b] = await allocatePorts(1);
		const nodeB = await startNode(t, b, {
			allowedSources: ['203.0.113.0/24'],
			ingressProtection: { blocklist: ['203.0.113.66/32'] },
		});
		const upstreamB = await startUdsUpstream(nodeB.socketPath);
		t.after(() => upstreamB.close());

		const admitted = await connectRaw(b.ingressPort);
		admitted.write(proxyV2Header('203.0.113.9', 4000));
		assert.equal(
			await tryEcho({ port: b.ingressPort, socket: admitted }),
			'ping',
			'allowedSources admits the asserted address'
		);
		assert.deepEqual(upstreamB.sources, ['203.0.113.9']);

		const blocked = new Promise<string>((resolve) => nodeB.proxy.once('blocked', (e) => resolve(e.ip)));
		const blockedSocket = await connectRaw(b.ingressPort);
		blockedSocket.write(proxyV2Header('203.0.113.66', 4000));
		assert.equal(await tryEcho({ port: b.ingressPort, socket: blockedSocket }), null);
		assert.equal(await blocked, '203.0.113.66');

		// The public listener sees the real 127.0.0.2, which allowedSources refuses.
		assert.equal(await tryEcho({ port: b.publicPort }), null);
		await sleep(50);
		assert.equal(upstreamB.sources.length, 1);
	});
});
