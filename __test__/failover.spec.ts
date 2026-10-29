/**
 * Peer failover across several symphony instances in one process. Each node has a public listener
 * and a `failoverIngress` listener, and its route's upstream is a Unix socket that may be absent.
 * Spill-over tests serve the upstream from a child process whose main thread can be kept busy, so
 * the load symphony measures is real thread CPU.
 *
 * The client connects from 127.0.0.2 (loopback on Linux) so the address the serving node's
 * upstream sees can be told apart from the forwarding node's own 127.0.0.1. macOS has that address
 * only with an `lo0` alias, and the suites that need it skip without one.
 */

import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import * as tls from 'node:tls';
import { after, describe, it, type TestContext } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import type { FailoverConfig, MtlsConfig, ProtectionConfig, RouteConfig, SpillConfig } from '../ts/types.js';
import { generateClientCa, generateSelfSignedCert, getFreePort, sleep } from './util.js';

const SNI = 'app.test';
const CLIENT_ADDRESS = '127.0.0.2';
const noClientAddress =
	process.platform !== 'linux' &&
	!Object.values(os.networkInterfaces()).some((addrs) => addrs?.some((a) => a.address === CLIENT_ADDRESS)) &&
	`${CLIENT_ADDRESS} is not a local address (macOS: sudo ifconfig lo0 alias ${CLIENT_ADDRESS})`;
const SUITE_TIMEOUT_MS = 60_000;
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

/**
 * Serves `startUdsUpstream`'s protocol from a worker thread of a child process, recording sources to
 * a file. With `busy`, the child's main thread spins, so `pid` (= its main thread's tid) reads ~100 %
 * CPU while the socket is still served. With `namespace`, the child runs in its own PID namespace and
 * `pid` is the id it sees there, as Harper in a container reports it.
 */
const UPSTREAM_THREAD = `
const fs = require('node:fs');
const net = require('node:net');
const { socketPath, sourcesFile, pidFile, pid } = require('node:worker_threads').workerData;
net.createServer((socket) => {
	socket.on('error', () => {});
	let pending = Buffer.alloc(0);
	socket.on('data', (chunk) => {
		if (pending === null) return void socket.write(chunk);
		pending = Buffer.concat([pending, chunk]);
		const end = pending.indexOf('\\r\\n');
		if (end < 0) return;
		fs.appendFileSync(sourcesFile, pending.subarray(0, end).toString().split(' ')[2] + '\\n');
		const rest = pending.subarray(end + 2);
		pending = null;
		if (rest.length > 0) socket.write(rest);
	});
}).listen(socketPath, () => fs.writeFileSync(pidFile, String(pid)));
`;
const UPSTREAM_PROCESS = `
const { Worker } = require('node:worker_threads');
const [socketPath, sourcesFile, pidFile, busy, thread] = process.argv.slice(1);
new Worker(thread, { eval: true, workerData: { socketPath, sourcesFile, pidFile, pid: process.pid } });
if (busy === '1') setTimeout(() => { for (;;); }, 20);
`;

const BWRAP = ['bwrap', '--unshare-pid', '--die-with-parent', '--dev-bind', '/', '/', '--proc', '/proc'];
const noPidNamespace =
	process.platform !== 'linux'
		? 'thread CPU is read from Linux /proc'
		: spawnSync(BWRAP[0], [...BWRAP.slice(1), 'true']).status !== 0 && 'bwrap cannot create a PID namespace here';

interface WorkerUpstream {
	socketPath: string;
	/** The child's pid, and its busy main thread's tid, as the child sees them. */
	pid: number;
	sources(): string[];
}

async function startWorkerUpstream(
	t: TestContext,
	opts: { busy?: boolean; namespace?: boolean } = {}
): Promise<WorkerUpstream> {
	const id = ++socketSeq;
	const socketPath = path.join(socketDir, `worker-${id}.sock`);
	const sourcesFile = path.join(socketDir, `worker-${id}.sources`);
	const pidFile = path.join(socketDir, `worker-${id}.pid`);
	const args = ['-e', UPSTREAM_PROCESS, socketPath, sourcesFile, pidFile, opts.busy ? '1' : '0', UPSTREAM_THREAD];
	const child = opts.namespace
		? spawn(BWRAP[0], [...BWRAP.slice(1), process.execPath, ...args], { stdio: 'ignore' })
		: spawn(process.execPath, args, { stdio: 'ignore' });
	t.after(() => void child.kill('SIGKILL'));
	await waitFor(() => fs.existsSync(pidFile) && fs.readFileSync(pidFile, 'utf8').length > 0, 10_000);
	return {
		socketPath,
		pid: Number(fs.readFileSync(pidFile, 'utf8')),
		sources: () => (fs.existsSync(sourcesFile) ? fs.readFileSync(sourcesFile, 'utf8').split('\n').filter(Boolean) : []),
	};
}

async function waitFor(condition: () => boolean, timeoutMs = 5000): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (!condition()) {
		if (Date.now() > deadline) throw new Error('timed out waiting for condition');
		await sleep(25);
	}
}

/** A PROXY v2 LOCAL header asking for the load of each named route (TLV 0xE3). */
function loadQuery(names: string[]): Buffer {
	const tlvs = Buffer.concat(
		names.map((name) => {
			const tlv = Buffer.alloc(3);
			tlv[0] = 0xe3;
			tlv.writeUInt16BE(Buffer.byteLength(name), 1);
			return Buffer.concat([tlv, Buffer.from(name)]);
		})
	);
	const header = Buffer.alloc(16);
	Buffer.from('0d0a0d0a000d0a515549540a', 'hex').copy(header, 0);
	header[12] = 0x20;
	header[13] = 0x00;
	header.writeUInt16BE(tlvs.length, 14);
	return Buffer.concat([header, tlvs]);
}

/** Everything the server sends before it closes. */
function readToEnd(socket: net.Socket): Promise<string> {
	return new Promise((resolve) => {
		let data = '';
		socket.on('data', (chunk: Buffer) => (data += chunk.toString()));
		socket.on('error', () => {});
		socket.on('close', () => resolve(data));
	});
}

/**
 * A stand-in failover peer. `answering` answers every load query with load 0 for each name; a
 * connection carrying a client (PROXY command) is closed without a byte. `legacy` closes load
 * queries too, as symphony 1.5.0 does.
 */
async function startFakePeer(t: TestContext, mode: 'answering' | 'legacy') {
	/** `answer` is what an answering peer reports for every name: a permille, or `-`. */
	const seen = { queries: 0, forwarded: 0, answer: '0' };
	const server = net.createServer((socket) => {
		socket.on('error', () => {});
		let buffered = Buffer.alloc(0);
		socket.on('data', (chunk: Buffer) => {
			buffered = Buffer.concat([buffered, chunk]);
			if (buffered.length < 16) return;
			if (buffered[12] !== 0x20) {
				seen.forwarded++;
				return void socket.destroy();
			}
			const len = buffered.readUInt16BE(14);
			if (buffered.length < 16 + len) return;
			seen.queries++;
			if (mode === 'legacy') return void socket.destroy();
			let names = 0;
			for (let at = 16; at < 16 + len; at += 3 + buffered.readUInt16BE(at + 1)) {
				if (buffered[at] === 0xe3) names++;
			}
			socket.end('SYMPHONY-LOAD/1\n' + `${seen.answer}\n`.repeat(names));
		});
	});
	await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
	t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
	return { port: (server.address() as net.AddressInfo).port, seen };
}

interface NodeOptions {
	peers?: number[];
	drain?: boolean;
	spill?: SpillConfig;
	probeIntervalMs?: number;
	/** An upstream started before the node, whose worker thread is the route's CPU sample. */
	upstream?: WorkerUpstream;
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
	const socketPath = opts.upstream?.socketPath ?? path.join(socketDir, `node-${++socketSeq}.sock`);
	const thread = opts.upstream && { pid: opts.upstream.pid, tid: opts.upstream.pid };
	const failoverRoute = (overrides: Partial<FailoverConfig> = {}): RouteConfig => ({
		sni: SNI,
		upstreams: [{ kind: 'uds', path: socketPath, ...thread }],
		terminateTls: true,
		cert: { certChain: cert, privateKey: key },
		mtls: opts.mtls,
		allowedSources: opts.allowedSources,
		failover: opts.peers
			? {
					peers: opts.peers.map((port) => ({ host: '127.0.0.1', port })),
					drain: opts.drain,
					probeIntervalMs: opts.probeIntervalMs ?? 50,
					peerCooldownMs: { min: 200, max: 1000 },
					spill: opts.spill,
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

function ingressMetrics(node: Node) {
	return node.proxy.metrics().listeners.find((l) => l.address === `127.0.0.1:${node.ingressPort}`)!;
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

describe('peer failover', { skip: noClientAddress, timeout: SUITE_TIMEOUT_MS }, () => {
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

	it('a draining route serves a connection locally when no peer takes it', async (t) => {
		const [a] = await allocatePorts(1);
		const deadPort = await getFreePort();
		const nodeA = await startNode(t, a, { peers: [deadPort], drain: true });
		const upstreamA = await startUdsUpstream(nodeA.socketPath);
		t.after(() => upstreamA.close());

		assert.equal(await tryEcho({ port: a.publicPort }), 'ping', 'the peer refused; served locally');
		assert.equal(await tryEcho({ port: a.publicPort }), 'ping', 'the peer is cooling down; served locally');
		assert.deepEqual(upstreamA.sources, [CLIENT_ADDRESS, CLIENT_ADDRESS]);
		const failover = routeMetrics(nodeA).failover!;
		assert.equal(failover.localFallbacks, 2);
		assert.equal(failover.exhausted, 0);
		assert.ok(count(failover.peers[0].failuresByReason, 'refused') >= 1);
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

describe(
	'spill-over',
	{
		skip: noClientAddress || (process.platform !== 'linux' && 'thread CPU is read from Linux /proc'),
		timeout: SUITE_TIMEOUT_MS,
	},
	() => {
		const spill: SpillConfig = { step: 1, maxFraction: 0.5 };

		it('spills a share of new connections to a less-loaded peer while the local threads are busy', async (t) => {
			const [a, b] = await allocatePorts(2);
			const hot = await startWorkerUpstream(t, { busy: true });
			const idle = await startWorkerUpstream(t);
			const nodeA = await startNode(t, a, { peers: [b.ingressPort], spill, upstream: hot });
			const nodeB = await startNode(t, b, { peers: [a.ingressPort], spill, upstream: idle });

			await waitFor(() => (routeMetrics(nodeA).failover!.spill?.fraction ?? 0) >= 0.5, 15_000);
			const before = routeMetrics(nodeA).failover!;
			assert.ok(before.spill!.localLoad! >= 0.75, `local load ${before.spill!.localLoad}`);
			assert.equal(before.spill!.target, `127.0.0.1:${b.ingressPort}`);
			assert.ok(before.peers[0].load! < 0.5, `peer load ${before.peers[0].load}`);
			assert.ok(before.peers[0].rttMs! > 0);

			const connections = 40;
			for (let i = 0; i < connections; i++) assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
			const spilled = routeMetrics(nodeA).failover!.peers[0].spilled;
			assert.ok(spilled > 0 && spilled < connections, `spilled ${spilled} of ${connections}`);
			assert.equal(idle.sources().length, spilled);
			assert.ok(
				idle.sources().every((source) => source === CLIENT_ADDRESS),
				'the peer sees the real client'
			);
			assert.equal(hot.sources().length, connections - spilled);
			assert.equal(routeMetrics(nodeA).failover!.peers[0].forwarded, 0, 'spilled, not failed over');

			const fromB = routeMetrics(nodeB).failover!;
			assert.equal(fromB.spill!.fraction, 0, 'the less-loaded node does not spill back');
			assert.equal(fromB.peers[0].spilled, 0);
			assert.ok(ingressMetrics(nodeB).loadQueries > 0);
			assert.ok(ingressMetrics(nodeA).loadQueries > 0);
		});

		it('at the default poll interval the share holds steadily, and stops as soon as the peer reports it is unavailable', async (t) => {
			const [a] = await allocatePorts(1);
			const peer = await startFakePeer(t, 'answering');
			const hot = await startWorkerUpstream(t, { busy: true });
			const nodeA = await startNode(t, a, { peers: [peer.port], spill, probeIntervalMs: 1000, upstream: hot });
			await waitFor(() => (routeMetrics(nodeA).failover!.spill?.fraction ?? 0) >= 0.5, 15_000);

			// Sampled across more than one poll: the admission is renewed before it expires.
			for (let i = 0; i < 60; i++) {
				assert.equal(routeMetrics(nodeA).failover!.spill!.fraction, 0.5, `sample ${i}`);
				await sleep(25);
			}

			peer.seen.answer = '-';
			const queries = peer.seen.queries;
			await waitFor(() => peer.seen.queries > queries, 3000);
			await waitFor(() => routeMetrics(nodeA).failover!.spill!.fraction === 0, 200);
			assert.equal(routeMetrics(nodeA).failover!.peers[0].load, undefined);
		});

		it('a spilled connection whose peer closes without answering is served locally', async (t) => {
			const [a] = await allocatePorts(1);
			const peer = await startFakePeer(t, 'answering');
			const hot = await startWorkerUpstream(t, { busy: true });
			const nodeA = await startNode(t, a, { peers: [peer.port], spill: { step: 1, maxFraction: 1 }, upstream: hot });
			await waitFor(() => (routeMetrics(nodeA).failover!.spill?.fraction ?? 0) >= 0.99, 15_000);

			assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
			assert.equal(peer.seen.forwarded, 1, 'the spill was attempted');
			assert.deepEqual(hot.sources(), [CLIENT_ADDRESS]);
			const failover = routeMetrics(nodeA).failover!;
			assert.equal(failover.localFallbacks, 1);
			assert.equal(count(failover.peers[0].failuresByReason, 'zero_byte_close'), 1);
			assert.equal(failover.peers[0].spilled, 0);
			assert.equal(failover.peers[0].coolingDown, true);
		});

		it('a peer that does not answer load queries, as 1.5.0 does not, is never a spill target', async (t) => {
			const [a] = await allocatePorts(1);
			const peer = await startFakePeer(t, 'legacy');
			const hot = await startWorkerUpstream(t, { busy: true });
			const nodeA = await startNode(t, a, { peers: [peer.port], spill, upstream: hot });
			await waitFor(() => (routeMetrics(nodeA).failover!.spill?.localLoad ?? 0) >= 0.75, 15_000);
			await waitFor(() => peer.seen.queries >= 5);

			const failover = routeMetrics(nodeA).failover!;
			assert.equal(failover.spill!.fraction, 0);
			assert.equal(failover.peers[0].load, undefined);
			assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
			assert.equal(peer.seen.forwarded, 0);
			assert.deepEqual(hot.sources(), [CLIENT_ADDRESS]);
		});
	}
);

describe('thread CPU under a PID namespace', { skip: noPidNamespace, timeout: SUITE_TIMEOUT_MS }, () => {
	it('reads the load of a worker that reports the ids of its own namespace', async (t) => {
		const [a] = await allocatePorts(1);
		const hot = await startWorkerUpstream(t, { busy: true, namespace: true });
		assert.ok(hot.pid < 100, `pid ${hot.pid} is the namespace's, not the host's`);
		const nodeA = await startNode(t, a, { peers: [await getFreePort()], spill: {}, upstream: hot });
		await waitFor(() => (routeMetrics(nodeA).failover!.spill?.localLoad ?? 0) >= 0.75, 15_000);
	});
});

describe('failover ingress', { timeout: SUITE_TIMEOUT_MS }, () => {
	it('answers a trusted load query per route name, and closes an untrusted one before reading', async (t) => {
		const [b, c] = await allocatePorts(2);
		const nodeB = await startNode(t, b);
		const query = await connectRaw(b.ingressPort);
		const answer = readToEnd(query);
		query.write(loadQuery([SNI, 'unknown.test', 'not a name']));
		// The route has no measured load (its upstream names no thread), so nothing is offered.
		assert.equal(await answer, 'SYMPHONY-LOAD/1\n-\n-\n-\n');
		assert.equal(ingressMetrics(nodeB).loadQueries, 1);

		const nodeC = await startNode(t, c, { trustedSources: ['10.0.0.0/8'] });
		const untrusted = await connectRaw(c.ingressPort);
		const nothing = readToEnd(untrusted);
		untrusted.write(loadQuery([SNI]));
		assert.equal(await nothing, '');
		assert.equal(count(ingressMetrics(nodeC).blockedByReason, 'untrusted_source'), 1);
		assert.equal(ingressMetrics(nodeC).loadQueries, 0);
	});

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

		// The public listener sees the real 127.0.0.1, which allowedSources refuses.
		assert.equal(
			await tryEcho({ port: b.publicPort, socket: net.connect({ host: '127.0.0.1', port: b.publicPort }) }),
			null
		);
		await sleep(50);
		assert.equal(upstreamB.sources.length, 1);
	});
});
