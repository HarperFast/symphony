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
import {
	clientHello,
	generateClientCa,
	generateSelfSignedCert,
	getFreePort,
	sleep,
	startSlowRelay as startRelay,
} from './util.js';

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
	accepted: number;
	closedWithNoBytes: number;
	close(): Promise<void>;
}

/**
 * Echo server on a Unix socket that records the PROXY v1 source address it was given.
 * `closeIdleAfterMs` closes a connection that has sent nothing by then, as Harper does, with
 * `farewell` as its last bytes.
 */
function startUdsUpstream(
	socketPath: string,
	opts: { closeIdleAfterMs?: number; farewell?: string } = {}
): Promise<UdsUpstream> {
	return new Promise((resolve, reject) => {
		const sources: string[] = [];
		const sockets = new Set<net.Socket>();
		const server = net.createServer((socket) => {
			upstream.accepted++;
			sockets.add(socket);
			let empty = true;
			socket.on('close', () => {
				sockets.delete(socket);
				if (empty) upstream.closedWithNoBytes++;
			});
			socket.on('error', () => {});
			if (opts.closeIdleAfterMs) {
				const idle = setTimeout(
					() => (opts.farewell ? socket.end(opts.farewell) : socket.destroy()),
					opts.closeIdleAfterMs
				);
				socket.once('data', () => clearTimeout(idle));
				socket.once('close', () => clearTimeout(idle));
			}
			let pending: Buffer | null = Buffer.alloc(0);
			socket.on('data', (chunk: Buffer) => {
				empty = false;
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
		const upstream: UdsUpstream = {
			sources,
			accepted: 0,
			closedWithNoBytes: 0,
			close: () =>
				new Promise((res) => {
					for (const s of sockets) s.destroy();
					server.close(() => res());
				}),
		};
		server.listen(socketPath, () => resolve(upstream));
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

const NON_ACCEPTING_LISTENER = `
const fs = require('node:fs');
require('node:net').createServer().listen({ port: 0, host: '127.0.0.1', backlog: 1 }, function () {
	fs.writeFileSync(process.argv[1], String(this.address().port));
	Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, process.argv[2] ? Number(process.argv[2]) : undefined);
});
`;

/**
 * A TCP address whose connects hang: its accept queue is full, so Linux drops further SYNs. `kill()`
 * ends the listener, after which a pending connect fails with ECONNREFUSED at its next SYN
 * retransmit, 1 s after it started. With `stallMs`, the listener starts accepting that long after it
 * bound, and a pending connect succeeds at that retransmit instead.
 */
async function startHangingUpstream(
	t: TestContext,
	stallMs?: number
): Promise<{ host: string; port: number; kill(): void }> {
	const portFile = path.join(socketDir, `hanging-${++socketSeq}.port`);
	const args = ['-e', NON_ACCEPTING_LISTENER, portFile, ...(stallMs ? [String(stallMs)] : [])];
	const child = spawn(process.execPath, args, { stdio: 'ignore' });
	t.after(() => void child.kill('SIGKILL'));
	await waitFor(() => fs.existsSync(portFile) && fs.readFileSync(portFile, 'utf8').length > 0, 10_000);
	const port = Number(fs.readFileSync(portFile, 'utf8'));
	const fillers: net.Socket[] = [];
	t.after(() => fillers.forEach((socket) => socket.destroy()));
	while (fillers.length < 64) {
		const filler = net.connect({ host: '127.0.0.1', port });
		filler.on('error', () => {});
		fillers.push(filler);
		const connected = await Promise.race([
			new Promise<boolean>((resolve) => filler.once('connect', () => resolve(true))),
			sleep(250).then(() => false),
		]);
		if (!connected) return { host: '127.0.0.1', port, kill: () => void child.kill('SIGKILL') };
	}
	throw new Error('the accept queue never filled');
}

async function startClosingUpstream(socketPath: string, closeAfterMs = 0) {
	let accepted = 0;
	const server = net.createServer({ pauseOnConnect: true }, (socket) => {
		accepted++;
		socket.on('error', () => {});
		setTimeout(() => socket.destroy(), closeAfterMs);
	});
	await new Promise<void>((resolve) => server.listen(socketPath, resolve));
	return {
		accepted: () => accepted,
		close: () => new Promise<void>((resolve) => server.close(() => resolve())),
	};
}

/**
 * What Docker's userland proxy does on a published port: accepts first, then dials the container, and
 * on a refused dial closes with the client's bytes unread.
 */
async function startDockerProxy(t: TestContext, port: number, backendPath: string) {
	let accepted = 0;
	const server = net.createServer({ pauseOnConnect: true }, (client) => {
		accepted++;
		client.on('error', () => {});
		const backend = net.connect(backendPath);
		backend.once('connect', () => {
			client.pipe(backend);
			backend.pipe(client);
			client.resume();
		});
		backend.on('error', () => client.destroy());
		client.once('close', () => backend.destroy());
	});
	await new Promise<void>((resolve) => server.listen(port, '127.0.0.1', resolve));
	t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));
	return { accepted: () => accepted };
}

/** A socket file with nothing listening on it, as a stopped container leaves behind. */
async function createStaleSocket(socketPath: string): Promise<void> {
	const upstream = await startUdsUpstream(socketPath);
	// Node unlinks the path it listened on when it closes, so the file is moved out of its reach.
	fs.renameSync(socketPath, `${socketPath}.moved`);
	await upstream.close();
	fs.renameSync(`${socketPath}.moved`, socketPath);
	const refused = await new Promise<string | undefined>((resolve) => {
		const probe = net.connect(socketPath, () => {
			probe.destroy();
			resolve(undefined);
		});
		probe.on('error', (e: NodeJS.ErrnoException) => resolve(e.code));
	});
	assert.equal(refused, 'ECONNREFUSED');
}

function startTlsUdsUpstream(t: TestContext, socketPath: string): Promise<void> {
	return new Promise((resolve, reject) => {
		const server = tls.createServer({ cert, key }, (socket) => {
			socket.on('error', () => {});
			socket.pipe(socket);
		});
		server.on('error', reject);
		t.after(() => new Promise<void>((res) => server.close(() => res())));
		server.listen(socketPath, resolve);
	});
}

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
 * queries too, as symphony 1.5.0 does. `silent` holds a client connection open without a byte.
 * `commits` sends one byte for a client connection and then closes.
 */
async function startFakePeer(t: TestContext, mode: 'answering' | 'legacy' | 'silent' | 'commits') {
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
				socket.removeAllListeners('data');
				if (mode === 'commits') socket.end('x');
				else if (mode !== 'silent') socket.destroy();
				return;
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
	passthrough?: boolean;
	tcpUpstream?: { host: string; port: number };
	socketPath?: string;
	publicProtection?: ProtectionConfig;
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

async function startSlowRelay(t: TestContext, port: number, delayMs: number): Promise<number> {
	const relay = await startRelay('127.0.0.1', port, delayMs);
	t.after(() => relay.close());
	return relay.port;
}

async function startNode(
	t: TestContext,
	ports: { publicPort: number; ingressPort: number },
	opts: NodeOptions = {}
): Promise<Node> {
	const socketPath = opts.socketPath ?? opts.upstream?.socketPath ?? path.join(socketDir, `node-${++socketSeq}.sock`);
	const thread = opts.upstream && { pid: opts.upstream.pid, tid: opts.upstream.pid };
	const failoverRoute = (overrides: Partial<FailoverConfig> = {}): RouteConfig => ({
		sni: SNI,
		upstreams: [opts.tcpUpstream ? { kind: 'tcp', ...opts.tcpUpstream } : { kind: 'uds', path: socketPath, ...thread }],
		terminateTls: !opts.passthrough,
		cert: opts.passthrough ? undefined : { certChain: cert, privateKey: key },
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
			{ host: '127.0.0.1', port: ports.publicPort, protection: opts.publicProtection },
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
	alpn?: string[];
	onSecure?(socket: tls.TLSSocket): void;
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
			ALPNProtocols: opts.alpn,
		});
		const timer = setTimeout(() => finish(null), 5000);
		const finish = (value: string | null) => {
			clearTimeout(timer);
			socket.destroy();
			resolve(value);
		};
		socket.on('secureConnect', () => {
			opts.onSecure?.(socket);
			socket.write(payload);
		});
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
 * Lose one connection to the absent local upstream and wait for the probe to report the route down.
 * Through the ingress listener, whose TLS-terminating routes connect after the handshake and which
 * never forwards, so no peer's counters move.
 */
async function markDown(node: Node): Promise<void> {
	const down = routeHealth(node.proxy, 'down');
	const socket = await connectRaw(node.ingressPort);
	socket.write(proxyV2Header(CLIENT_ADDRESS, 4000));
	assert.equal(await tryEcho({ port: node.ingressPort, socket }), null, 'the connection that finds out is lost');
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

	it(
		'forwards to a peer while a TCP upstream is unreachable',
		{ skip: process.platform !== 'linux' && 'needs Linux to make a TCP connect fail as unreachable' },
		async (t) => {
			const [a, b] = await allocatePorts(2);
			const nodeA = await startNode(t, a, {
				routes: [
					{
						sni: SNI,
						upstreams: [{ kind: 'tcp', host: '255.255.255.255', port: 9 }],
						terminateTls: false,
						failover: {
							peers: [{ host: '127.0.0.1', port: b.ingressPort }],
							probeIntervalMs: 50,
							peerCooldownMs: { min: 200, max: 1000 },
						},
					},
				],
			});
			const nodeB = await startNode(t, b, { peers: [a.ingressPort] });
			const upstreamB = await startUdsUpstream(nodeB.socketPath);
			t.after(() => upstreamB.close());

			const down = routeHealth(nodeA.proxy, 'down');
			assert.equal(await tryEcho({ port: a.publicPort }), 'ping', 'the connection that finds out');
			await down;
			assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
			assert.deepEqual(upstreamB.sources, [CLIENT_ADDRESS, CLIENT_ADDRESS]);

			const route = routeMetrics(nodeA);
			assert.equal(count(route.errorsByReason, 'upstream_connect'), 1, 'the second connection did not try it');
			assert.equal(route.failover!.localUp, false);
			assert.equal(route.failover!.refusingSlots, 1);
			assert.equal(route.failover!.peers[0].forwarded, 2);
		}
	);

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

const routeModes: [string, boolean][] = [
	['passthrough', true],
	['TLS-terminating', false],
];
for (const [mode, passthrough] of routeModes) {
	describe(
		`a failed local connect on a ${mode} failover route`,
		{ skip: noClientAddress, timeout: SUITE_TIMEOUT_MS },
		() => {
			const localUpstreams: [string, () => Promise<NodeOptions>][] = [
				[
					'a TCP port nothing listens on',
					async () => ({ tcpUpstream: { host: '127.0.0.1', port: await getFreePort() } }),
				],
				['a Unix socket file that is missing', async () => ({})],
				[
					'a Unix socket file nothing listens on',
					async () => {
						const socketPath = path.join(socketDir, `stale-${++socketSeq}.sock`);
						await createStaleSocket(socketPath);
						return { socketPath };
					},
				],
			];
			for (const [name, localUpstream] of localUpstreams) {
				it(`serves the first connection from a peer, with ${name}`, async (t) => {
					const [a, b] = await allocatePorts(2);
					const nodeA = await startNode(t, a, { peers: [b.ingressPort], passthrough, ...(await localUpstream()) });
					const nodeB = await startNode(t, b);
					const upstreamB = await startUdsUpstream(nodeB.socketPath);
					t.after(() => upstreamB.close());

					assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
					assert.deepEqual(upstreamB.sources, [CLIENT_ADDRESS], 'the peer sees the real client');
					const route = routeMetrics(nodeA);
					assert.equal(count(route.errorsByReason, 'upstream_connect'), 1, 'the local failure is counted');
					assert.equal(route.failover!.refusingSlots, 1, 'the slot is marked');
					assert.equal(route.failover!.peers[0].forwarded, 1);
					assert.equal(route.failover!.exhausted, 0);

					assert.equal(await tryEcho({ port: a.publicPort }), 'ping', 'later connections go straight to the peer');
					assert.equal(count(routeMetrics(nodeA).errorsByReason, 'upstream_connect'), 1);
					assert.equal(routeMetrics(nodeA).failover!.peers[0].forwarded, 2);
				});
			}

			it(
				'forwards on a connect error that is not a refusal, and marks nothing',
				{ skip: process.getuid?.() === 0 && 'root ignores socket file permissions' },
				async (t) => {
					const [a, b] = await allocatePorts(2);
					const nodeA = await startNode(t, a, { peers: [b.ingressPort], passthrough });
					const upstreamA = await startUdsUpstream(nodeA.socketPath);
					t.after(() => upstreamA.close());
					fs.chmodSync(nodeA.socketPath, 0);
					const nodeB = await startNode(t, b);
					const upstreamB = await startUdsUpstream(nodeB.socketPath);
					t.after(() => upstreamB.close());

					assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
					assert.equal(upstreamB.sources.length, 1);
					assert.equal(upstreamA.sources.length, 0);
					const route = routeMetrics(nodeA);
					assert.equal(count(route.errorsByReason, 'upstream_connect'), 1);
					assert.equal(route.failover!.refusingSlots, 0);
					assert.equal(route.failover!.peers[0].forwarded, 1);
				}
			);

			it('closes the client when every peer refuses, counting one upstream_connect', async (t) => {
				const [a] = await allocatePorts(1);
				const nodeA = await startNode(t, a, { peers: [await getFreePort()], passthrough });

				assert.equal(await tryEcho({ port: a.publicPort }), null);
				const route = routeMetrics(nodeA);
				assert.equal(count(route.errorsByReason, 'upstream_connect'), 1);
				assert.equal(route.failover!.exhausted, 1);
				assert.equal(count(route.failover!.peers[0].failuresByReason, 'refused'), 1);
			});

			it('tries the peers again when a draining route falls back to a local upstream that refuses', async (t) => {
				const [a] = await allocatePorts(1);
				const nodeA = await startNode(t, a, { peers: [await getFreePort()], passthrough, drain: true });

				assert.equal(await tryEcho({ port: a.publicPort }), null);
				const failover = routeMetrics(nodeA).failover!;
				assert.equal(failover.localFallbacks, 1);
				assert.equal(failover.exhausted, 1);
				assert.equal(count(failover.peers[0].failuresByReason, 'refused'), 2);
			});

			it('a suspended route does not forward when its resolved upstream refuses', async (t) => {
				const [a] = await allocatePorts(1);
				const peer = await startFakePeer(t, 'answering');
				const deadPort = await getFreePort();
				const nodeA = await startNode(t, a, {
					routes: [
						{
							sni: SNI,
							upstreams: [],
							terminateTls: false,
							suspended: true,
							suspendTimeoutMs: 2000,
							failover: { peers: [{ host: '127.0.0.1', port: peer.port }] },
						},
					],
				});
				nodeA.proxy.on('suspended', (conn) =>
					nodeA.proxy.resolveConnection(conn.id, {
						upstream: { kind: 'tcp', host: '127.0.0.1', port: deadPort },
						terminateTls: !passthrough,
						cert: passthrough ? undefined : { certChain: cert, privateKey: key },
					})
				);

				assert.equal(await tryEcho({ port: a.publicPort }), null);
				await sleep(50);
				assert.equal(peer.seen.forwarded, 0);
				assert.equal(count(routeMetrics(nodeA).errorsByReason, 'upstream_connect'), 1);
			});

			describe(
				'whose connect times out',
				{ skip: process.platform !== 'linux' && 'relies on Linux dropping SYNs' },
				() => {
					const handshakeMs = 2000;

					it('gives the peer the rest of the handshake timeout', async (t) => {
						const [a, b] = await allocatePorts(2);
						const nodeA = await startNode(t, a, {
							peers: [b.ingressPort],
							passthrough,
							tcpUpstream: await startHangingUpstream(t),
							publicProtection: { tlsHandshakeTimeoutMs: handshakeMs },
						});
						const nodeB = await startNode(t, b);
						const upstreamB = await startUdsUpstream(nodeB.socketPath);
						t.after(() => upstreamB.close());

						const started = performance.now();
						assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
						const elapsed = performance.now() - started;
						assert.ok(elapsed >= handshakeMs * 0.4, `the local connect was given time: ${elapsed} ms`);
						assert.ok(elapsed < handshakeMs, `within the handshake timeout: ${elapsed} ms`);
						const route = routeMetrics(nodeA);
						assert.equal(count(route.errorsByReason, 'upstream_connect'), 1);
						assert.equal(route.failover!.refusingSlots, 1);
					});

					it('closes a client no peer answered at the end of the handshake timeout', async (t) => {
						const [a] = await allocatePorts(1);
						const peer = await startFakePeer(t, 'silent');
						const nodeA = await startNode(t, a, {
							peers: [peer.port],
							passthrough,
							tcpUpstream: await startHangingUpstream(t),
							publicProtection: { tlsHandshakeTimeoutMs: handshakeMs },
						});

						const started = performance.now();
						assert.equal(await tryEcho({ port: a.publicPort }), null);
						const elapsed = performance.now() - started;
						assert.equal(peer.seen.forwarded, 1, 'the peer was tried');
						assert.ok(elapsed >= handshakeMs * 0.9, `the peer was given the rest: ${elapsed} ms`);
						assert.ok(elapsed < handshakeMs + 500, `the total stays within the handshake timeout: ${elapsed} ms`);
						const failover = routeMetrics(nodeA).failover!;
						assert.equal(count(failover.peers[0].failuresByReason, 'timeout'), 1);
						assert.equal(failover.exhausted, 1);
					});

					it('keeps one allowance across a silent drain peer, the local connect and a silent peer', async (t) => {
						const [a] = await allocatePorts(1);
						const peer = await startFakePeer(t, 'silent');
						const nodeA = await startNode(t, a, {
							peers: [peer.port],
							passthrough,
							drain: true,
							tcpUpstream: await startHangingUpstream(t),
							publicProtection: { tlsHandshakeTimeoutMs: handshakeMs },
						});

						const started = performance.now();
						assert.equal(await tryEcho({ port: a.publicPort }), null);
						const elapsed = performance.now() - started;
						assert.equal(peer.seen.forwarded, 2, 'tried by the drain, and again once the local connect failed');
						assert.ok(elapsed >= handshakeMs * 0.9, `the allowance was used: ${elapsed} ms`);
						assert.ok(elapsed < handshakeMs + 500, `and not exceeded: ${elapsed} ms`);
						const failover = routeMetrics(nodeA).failover!;
						assert.equal(failover.localFallbacks, 1);
						assert.equal(failover.exhausted, 1);
					});
				}
			);

			describe(
				'whose connect fails slowly',
				{ skip: process.platform !== 'linux' && 'relies on Linux dropping SYNs' },
				() => {
					// The local connect is capped at half of this, later than the 1 s SYN retransmit that fails it.
					const handshakeMs = 3000;
					async function startDyingNode(
						t: TestContext,
						ports: { publicPort: number; ingressPort: number },
						peer: number
					): Promise<{ node: Node; killUpstream(): void }> {
						const upstream = await startHangingUpstream(t);
						const node = await startNode(t, ports, {
							peers: [peer],
							passthrough,
							tcpUpstream: { host: upstream.host, port: upstream.port },
							publicProtection: { tlsHandshakeTimeoutMs: handshakeMs },
						});
						return { node, killUpstream: upstream.kill };
					}

					it('gives the peer the time that is left', async (t) => {
						const [a, b] = await allocatePorts(2);
						const nodeB = await startNode(t, b);
						const upstreamB = await startUdsUpstream(nodeB.socketPath);
						t.after(() => upstreamB.close());
						const { node: nodeA, killUpstream } = await startDyingNode(t, a, b.ingressPort);

						const started = performance.now();
						const reply = tryEcho({ port: a.publicPort });
						setTimeout(killUpstream, 200);
						assert.equal(await reply, 'ping');
						const elapsed = performance.now() - started;
						assert.ok(elapsed >= 900, `the connect failed at its retransmit: ${elapsed} ms`);
						assert.ok(elapsed < handshakeMs / 2, `before the cap: ${elapsed} ms`);
						assert.equal(count(routeMetrics(nodeA).errorsByReason, 'upstream_connect'), 1);
					});

					it('closes at the end of the handshake timeout when the peer stays silent', async (t) => {
						const [a] = await allocatePorts(1);
						const peer = await startFakePeer(t, 'silent');
						const { node: nodeA, killUpstream } = await startDyingNode(t, a, peer.port);

						const started = performance.now();
						const reply = tryEcho({ port: a.publicPort });
						setTimeout(killUpstream, 200);
						assert.equal(await reply, null);
						const elapsed = performance.now() - started;
						assert.equal(peer.seen.forwarded, 1);
						assert.ok(elapsed >= handshakeMs * 0.9, `the peer was given the rest: ${elapsed} ms`);
						assert.ok(elapsed < handshakeMs + 500, `the total stays within the handshake timeout: ${elapsed} ms`);
						assert.equal(routeMetrics(nodeA).failover!.exhausted, 1);
					});
				}
			);

			it('closes a connection whose local upstream accepts and then resets, without a peer', async (t) => {
				const [a] = await allocatePorts(1);
				const peer = await startFakePeer(t, 'answering');
				const nodeA = await startNode(t, a, { peers: [peer.port], passthrough });
				const server = net.createServer((socket) => socket.destroy());
				await new Promise<void>((resolve) => server.listen(nodeA.socketPath, resolve));
				t.after(() => new Promise<void>((resolve) => server.close(() => resolve())));

				assert.equal(await tryEcho({ port: a.publicPort }), null);
				await sleep(50);
				assert.equal(peer.seen.forwarded, 0);
				assert.equal(count(routeMetrics(nodeA).errorsByReason, 'upstream_connect'), 0);
			});

			it('a peer that answered is not retried when it then closes', async (t) => {
				const [a] = await allocatePorts(1);
				const committing = await startFakePeer(t, 'commits');
				const next = await startFakePeer(t, 'answering');
				const nodeA = await startNode(t, a, { peers: [committing.port, next.port], passthrough });

				assert.equal(await tryEcho({ port: a.publicPort }), null);
				await sleep(50);
				assert.equal(committing.seen.forwarded, 1);
				assert.equal(next.seen.forwarded, 0);
				const failover = routeMetrics(nodeA).failover!;
				assert.equal(failover.peers[0].forwarded, 1);
				assert.equal(failover.replays, 0);
			});
		}
	);
}

describe('a passthrough failover route', { skip: noClientAddress, timeout: SUITE_TIMEOUT_MS }, () => {
	it('reaches a TLS server behind the peer when both nodes pass through', async (t) => {
		const [a, b] = await allocatePorts(2);
		const nodeA = await startNode(t, a, { peers: [b.ingressPort], passthrough: true });
		const upstreamPath = path.join(socketDir, `tls-${++socketSeq}.sock`);
		await startTlsUdsUpstream(t, upstreamPath);
		await startNode(t, b, {
			routes: [
				{
					sni: SNI,
					upstreams: [{ kind: 'uds', path: upstreamPath }],
					terminateTls: false,
					sourceAddressHeader: 'none',
				},
			],
		});

		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(routeMetrics(nodeA).failover!.peers[0].forwarded, 1);
	});

	it('serves a local upstream that accepts, without a peer', async (t) => {
		const [a] = await allocatePorts(1);
		const peer = await startFakePeer(t, 'answering');
		const nodeA = await startNode(t, a, { peers: [peer.port], passthrough: true });
		const upstreamA = await startUdsUpstream(nodeA.socketPath);
		t.after(() => upstreamA.close());

		const hello = clientHello(SNI);
		const client = await connectRaw(a.publicPort);
		t.after(() => void client.destroy());
		const echoed = new Promise<number>((resolve) => client.once('data', (chunk: Buffer) => resolve(chunk.length)));
		client.write(hello);
		assert.equal(await echoed, hello.length);
		assert.equal(upstreamA.sources.length, 1);
		assert.equal(peer.seen.forwarded, 0);
		assert.deepEqual(routeMetrics(nodeA).errorsByReason, []);
	});

	it('an ingress connection is closed with no bytes and goes to no peer, so the forwarder moves on', async (t) => {
		const [a, b, c] = await allocatePorts(3);
		const peerOfB = await startFakePeer(t, 'answering');
		const nodeA = await startNode(t, a, { peers: [b.ingressPort, c.ingressPort], passthrough: true });
		const nodeB = await startNode(t, b, { peers: [peerOfB.port], passthrough: true });
		const nodeC = await startNode(t, c);
		const upstreamC = await startUdsUpstream(nodeC.socketPath);
		t.after(() => upstreamC.close());

		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(upstreamC.sources.length, 1);
		const failoverA = routeMetrics(nodeA).failover!;
		assert.equal(count(failoverA.peers[0].failuresByReason, 'zero_byte_close'), 1);
		assert.equal(failoverA.replays, 1);
		const routeB = routeMetrics(nodeB);
		assert.equal(count(routeB.errorsByReason, 'upstream_connect'), 1);
		assert.equal(routeB.failover!.exhausted, 0);
		assert.equal(routeB.failover!.peers[0].forwarded, 0);
		assert.equal(peerOfB.seen.forwarded, 0);
	});
});

describe('a TLS-terminating failover route', { skip: noClientAddress, timeout: SUITE_TIMEOUT_MS }, () => {
	function nextSocket(): string {
		return path.join(socketDir, `split-${++socketSeq}.sock`);
	}

	function splitRoute(h1Path: string, h2Path: string, peers: number[]): RouteConfig {
		return {
			sni: SNI,
			upstreams: [
				{ kind: 'uds', path: h1Path },
				{ kind: 'uds', path: h2Path, protocol: 'h2' },
			],
			terminateTls: true,
			http2: true,
			cert: { certChain: cert, privateKey: key },
			failover: {
				peers: peers.map((port) => ({ host: '127.0.0.1', port })),
				probeIntervalMs: 50,
				peerCooldownMs: { min: 200, max: 1000 },
			},
		};
	}

	it('uses the connection it made before the handshake, without a second connect', async (t) => {
		const [a] = await allocatePorts(1);
		const peer = await startFakePeer(t, 'answering');
		const nodeA = await startNode(t, a, { peers: [peer.port] });
		const upstreamA = await startUdsUpstream(nodeA.socketPath);
		t.after(() => upstreamA.close());

		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(upstreamA.accepted, 1);
		assert.deepEqual(upstreamA.sources, [CLIENT_ADDRESS]);
		assert.equal(peer.seen.forwarded, 0);
		assert.equal(count(routeMetrics(nodeA).errorsByReason, 'upstream_connect'), 0);
	});

	it('connects each client only to the destination its protocol selects', async (t) => {
		const [a] = await allocatePorts(1);
		const peer = await startFakePeer(t, 'answering');
		const [h1Path, h2Path] = [nextSocket(), nextSocket()];
		const h1 = await startUdsUpstream(h1Path);
		const h2 = await startUdsUpstream(h2Path);
		t.after(() => h1.close());
		t.after(() => h2.close());
		await startNode(t, a, { routes: [splitRoute(h1Path, h2Path, [peer.port])] });

		const cases: [string[] | undefined, UdsUpstream, string | false][] = [
			[['h2'], h2, 'h2'],
			[['http/1.1', 'h2'], h2, 'h2'],
			[['h2', 'http/1.1'], h2, 'h2'],
			[['http/1.1'], h1, 'http/1.1'],
			[undefined, h1, false],
		];
		for (const [alpn, served, expected] of cases) {
			const before = served.sources.length;
			let negotiated: string | false | null = null;
			const reply = await tryEcho({ port: a.publicPort, alpn, onSecure: (s) => (negotiated = s.alpnProtocol) });
			assert.equal(reply, 'ping', `offer ${alpn}`);
			assert.equal(negotiated, expected, `offer ${alpn}`);
			assert.equal(served.sources.length, before + 1, `offer ${alpn}`);
		}
		assert.equal(h2.accepted, 3, 'no connection to the h1 destination for an h2 client, or the reverse');
		assert.equal(h1.accepted, 2);
		assert.equal(h1.closedWithNoBytes + h2.closedWithNoBytes, 0);
		assert.equal(peer.seen.forwarded, 0);
	});

	it('with only its h2 destination refusing, forwards an h2 client and serves an h1 client until the route is marked', async (t) => {
		const [a, b] = await allocatePorts(2);
		const [h1Path, absentH2] = [nextSocket(), nextSocket()];
		const h1 = await startUdsUpstream(h1Path);
		t.after(() => h1.close());
		const nodeA = await startNode(t, a, { routes: [splitRoute(h1Path, absentH2, [b.ingressPort])] });
		const peerPath = nextSocket();
		const upstreamB = await startUdsUpstream(peerPath);
		t.after(() => upstreamB.close());
		await startNode(t, b, {
			routes: [
				{
					sni: SNI,
					upstreams: [{ kind: 'uds', path: peerPath }],
					terminateTls: true,
					http2: true,
					cert: { certChain: cert, privateKey: key },
				},
			],
		});

		assert.equal(await tryEcho({ port: a.publicPort, alpn: ['http/1.1'] }), 'ping');
		assert.equal(h1.sources.length, 1, 'nothing marked yet: served locally');
		assert.equal(upstreamB.sources.length, 0);

		let negotiated: string | false | null = null;
		const reply = await tryEcho({
			port: a.publicPort,
			alpn: ['http/1.1', 'h2'],
			onSecure: (s) => (negotiated = s.alpnProtocol),
		});
		assert.equal(reply, 'ping');
		assert.equal(negotiated, 'h2', 'negotiated with the peer');
		assert.deepEqual(upstreamB.sources, [CLIENT_ADDRESS]);
		assert.equal(count(routeMetrics(nodeA).errorsByReason, 'upstream_connect'), 1);
		assert.equal(routeMetrics(nodeA).failover!.refusingSlots, 1);

		// A refusing h2 destination now means the route is down, for either protocol.
		assert.equal(await tryEcho({ port: a.publicPort, alpn: ['http/1.1'] }), 'ping');
		assert.equal(h1.sources.length, 1);
		assert.equal(upstreamB.sources.length, 2);
		assert.equal(count(routeMetrics(nodeA).errorsByReason, 'upstream_connect'), 1);
	});

	it('connects after the handshake for a hello too large to replay, which a healthy h2 destination still serves', async (t) => {
		const [a] = await allocatePorts(1);
		const peer = await startFakePeer(t, 'answering');
		const [absentH1, h2Path] = [nextSocket(), nextSocket()];
		const h2 = await startUdsUpstream(h2Path);
		t.after(() => h2.close());
		const nodeA = await startNode(t, a, { routes: [splitRoute(absentH1, h2Path, [peer.port])] });

		// Over symphony's 16 KiB hello cap: the name is parsed, the offer past the cap is not.
		const filler = Array.from({ length: 100 }, (_, i) => `filler-${i}-`.padEnd(200, 'x'));
		assert.equal(await tryEcho({ port: a.publicPort, alpn: [...filler, 'h2'] }), 'ping');
		assert.equal(h2.sources.length, 1);
		assert.equal(peer.seen.forwarded, 0);
		const route = routeMetrics(nodeA);
		assert.equal(count(route.errorsByReason, 'upstream_connect'), 0);
		assert.equal(route.failover!.refusingSlots, 0);
	});

	it('closes the upstream with no bytes when a client fails its handshake, and tries no peer', async (t) => {
		const [a] = await allocatePorts(1);
		const peer = await startFakePeer(t, 'answering');
		const [h1Path, h2Path] = [nextSocket(), nextSocket()];
		const h1 = await startUdsUpstream(h1Path);
		const h2 = await startUdsUpstream(h2Path);
		t.after(() => h1.close());
		t.after(() => h2.close());
		const nodeA = await startNode(t, a, { routes: [splitRoute(h1Path, h2Path, [peer.port])] });

		assert.equal(await tryEcho({ port: a.publicPort, alpn: ['mqtt'] }), null, 'no protocol in common');
		await waitFor(() => h1.closedWithNoBytes === 1);
		assert.equal(h1.accepted, 1);
		assert.equal(h1.sources.length, 0);
		assert.equal(h2.accepted, 0);
		assert.equal(peer.seen.forwarded, 0);
		const route = routeMetrics(nodeA);
		assert.equal(count(route.errorsByReason, 'tls_handshake'), 1);
		assert.equal(count(route.errorsByReason, 'upstream_connect'), 0);
	});

	describe('that requires a client certificate', () => {
		it('lets no client reach its upstream before the certificate is verified', async (t) => {
			const ca = generateClientCa();
			const [a] = await allocatePorts(1);
			const peer = await startFakePeer(t, 'answering');
			const nodeA = await startNode(t, a, {
				peers: [peer.port],
				mtls: { clientCaCert: ca.caCert, requireClientCert: true },
			});
			const upstreamA = await startUdsUpstream(nodeA.socketPath);
			t.after(() => upstreamA.close());

			assert.equal(await tryEcho({ port: a.publicPort }), null);
			await sleep(50);
			assert.equal(upstreamA.accepted, 0);
			assert.equal(count(routeMetrics(nodeA).errorsByReason, 'tls_handshake'), 1);

			assert.equal(await tryEcho({ port: a.publicPort, clientCert: ca.clientCert, clientKey: ca.clientKey }), 'ping');
			assert.equal(upstreamA.accepted, 1);
			assert.equal(upstreamA.sources.length, 1);
			assert.equal(peer.seen.forwarded, 0);
		});

		it('loses the connection that finds its upstream dead, and forwards once the slot is marked', async (t) => {
			const ca = generateClientCa();
			const [a, b] = await allocatePorts(2);
			const client = { clientCert: ca.clientCert, clientKey: ca.clientKey };
			const mtls = { clientCaCert: ca.caCert, requireClientCert: true };
			const nodeA = await startNode(t, a, { peers: [b.ingressPort], mtls });
			const nodeB = await startNode(t, b, { mtls });
			const upstreamB = await startUdsUpstream(nodeB.socketPath);
			t.after(() => upstreamB.close());

			assert.equal(await tryEcho({ port: a.publicPort, ...client }), null);
			assert.equal(count(routeMetrics(nodeA).errorsByReason, 'upstream_connect'), 1);
			assert.equal(routeMetrics(nodeA).failover!.peers[0].forwarded, 0);

			assert.equal(await tryEcho({ port: a.publicPort, ...client }), 'ping');
			assert.equal(routeMetrics(nodeA).failover!.peers[0].forwarded, 1);
			assert.equal(upstreamB.sources.length, 1);
		});
	});

	it('closes the upstream when a client abandons its handshake', async (t) => {
		const [a] = await allocatePorts(1);
		const peer = await startFakePeer(t, 'answering');
		const nodeA = await startNode(t, a, { peers: [peer.port] });
		const upstreamA = await startUdsUpstream(nodeA.socketPath);
		t.after(() => upstreamA.close());
		const relay = await startSlowRelay(t, a.publicPort, 60_000);

		const socket = net.connect({ host: '127.0.0.1', port: relay });
		const client = tls.connect({ socket, servername: SNI, rejectUnauthorized: false });
		client.on('error', () => {});
		await waitFor(() => upstreamA.accepted === 1);
		assert.equal(upstreamA.closedWithNoBytes, 0, 'held across the handshake');
		client.destroy();
		await waitFor(() => upstreamA.closedWithNoBytes === 1);
		assert.equal(peer.seen.forwarded, 0);
	});

	for (const [how, farewell] of [
		['with nothing unread', undefined],
		['behind unread bytes', 'bye'],
	] as const) {
		it(`replaces a connection the upstream closed during a slow handshake, ${how}`, async (t) => {
			const [a] = await allocatePorts(1);
			const peer = await startFakePeer(t, 'answering');
			const nodeA = await startNode(t, a, { peers: [peer.port] });
			const upstreamA = await startUdsUpstream(nodeA.socketPath, { closeIdleAfterMs: 100, farewell });
			t.after(() => upstreamA.close());
			const relay = await startSlowRelay(t, a.publicPort, 400);

			const socket = net.connect({ host: '127.0.0.1', port: relay });
			assert.equal(await tryEcho({ port: relay, socket }), 'ping');
			assert.equal(upstreamA.accepted, 2);
			assert.equal(upstreamA.sources.length, 1);
			assert.equal(peer.seen.forwarded, 0);
			assert.equal(count(routeMetrics(nodeA).errorsByReason, 'upstream_connect'), 0);
			await waitFor(() => upstreamA.closedWithNoBytes === 1);
		});
	}

	it('loses the connection, once counted, when the upstream stops during the handshake', async (t) => {
		const [a] = await allocatePorts(1);
		const peer = await startFakePeer(t, 'answering');
		const nodeA = await startNode(t, a, { peers: [peer.port] });
		const upstreamA = await startUdsUpstream(nodeA.socketPath);
		const relay = await startSlowRelay(t, a.publicPort, 400);

		const socket = net.connect({ host: '127.0.0.1', port: relay });
		const reply = tryEcho({ port: relay, socket });
		await waitFor(() => upstreamA.accepted === 1);
		await upstreamA.close();
		assert.equal(await reply, null);
		await sleep(50);
		assert.equal(peer.seen.forwarded, 0, 'the hello was consumed: too late for a peer');
		const route = routeMetrics(nodeA);
		assert.equal(count(route.errorsByReason, 'upstream_connect'), 1);
		assert.equal(route.failover!.peers[0].forwarded, 0);
		assert.equal(route.failover!.refusingSlots, 1);
	});

	it('tries its other local slots before any peer', async (t) => {
		const [a] = await allocatePorts(1);
		const peer = await startFakePeer(t, 'answering');
		const [absent, live] = [nextSocket(), nextSocket()];
		const upstreamA = await startUdsUpstream(live);
		t.after(() => upstreamA.close());
		const route = splitRoute(absent, live, [peer.port]);
		route.upstreams = [
			{ kind: 'uds', path: absent },
			{ kind: 'uds', path: live },
		];
		const nodeA = await startNode(t, a, { routes: [route] });

		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(upstreamA.sources.length, 1);
		assert.equal(peer.seen.forwarded, 0);
		const metrics = routeMetrics(nodeA);
		assert.equal(count(metrics.errorsByReason, 'upstream_connect'), 0);
		assert.equal(metrics.failover!.refusingSlots, 1);
	});

	it('on the ingress listener still connects after its handshake, and goes to no peer', async (t) => {
		const [b] = await allocatePorts(1);
		const peerOfB = await startFakePeer(t, 'answering');
		const nodeB = await startNode(t, b, { peers: [peerOfB.port] });

		const socket = await connectRaw(b.ingressPort);
		socket.write(proxyV2Header(CLIENT_ADDRESS, 4000));
		let handshakeFinished = false;
		const reply = await tryEcho({ port: b.ingressPort, socket, onSecure: () => (handshakeFinished = true) });
		assert.equal(reply, null);
		assert.ok(handshakeFinished);
		await sleep(50);
		const route = routeMetrics(nodeB);
		assert.equal(count(route.errorsByReason, 'upstream_connect'), 1);
		assert.equal(route.failover!.peers[0].forwarded, 0);
		assert.equal(route.failover!.exhausted, 0);
		assert.equal(peerOfB.seen.forwarded, 0);
	});

	it(
		'gives the handshake only what a slow local connect left of the timeout',
		{ skip: process.platform !== 'linux' && 'relies on Linux dropping SYNs' },
		async (t) => {
			const handshakeMs = 3000;
			const [a] = await allocatePorts(1);
			const peer = await startFakePeer(t, 'answering');
			const upstream = await startHangingUpstream(t, 800);
			const nodeA = await startNode(t, a, {
				peers: [peer.port],
				tcpUpstream: { host: upstream.host, port: upstream.port },
				publicProtection: { tlsHandshakeTimeoutMs: handshakeMs },
			});
			const relay = await startSlowRelay(t, a.publicPort, 60_000);

			const started = performance.now();
			const socket = net.connect({ host: '127.0.0.1', port: relay });
			const client = tls.connect({ socket, servername: SNI, rejectUnauthorized: false });
			client.on('error', () => {});
			await Promise.race([new Promise((resolve) => client.once('close', resolve)), sleep(handshakeMs * 2)]);
			const elapsed = performance.now() - started;
			assert.ok(elapsed >= handshakeMs * 0.9, `the handshake had the rest: ${elapsed} ms`);
			assert.ok(elapsed < handshakeMs + 500, `and no more: ${elapsed} ms`);
			const route = routeMetrics(nodeA);
			assert.equal(count(route.errorsByReason, 'tls_handshake'), 1);
			assert.equal(count(route.errorsByReason, 'upstream_connect'), 0, 'the connect succeeded');
			assert.equal(peer.seen.forwarded, 0);
		}
	);
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

describe('an upstream that accepts before it serves', { skip: noClientAddress, timeout: SUITE_TIMEOUT_MS }, () => {
	async function startPeer(t: TestContext) {
		const [ports] = await allocatePorts(1);
		const node = await startNode(t, ports);
		const upstream = await startUdsUpstream(node.socketPath);
		t.after(() => upstream.close());
		return { node, upstream };
	}

	function recordHealth(proxy: SymphonyProxy): string[] {
		const events: string[] = [];
		proxy.on('routeHealth', (event: { status: string }) => events.push(event.status));
		return events;
	}

	async function assertServedByPeerOnly(node: Node, forwardedBefore: number) {
		for (let i = 0; i < 3; i++) assert.equal(await tryEcho({ port: node.publicPort }), 'ping');
		const route = routeMetrics(node);
		assert.equal(route.failover!.localUp, false);
		assert.equal(route.failover!.peers[0].forwarded, forwardedBefore + 3);
		assert.equal(count(route.errorsByReason, 'stream'), 0);
	}

	function tcpRoute(port: number, peer: number): RouteConfig {
		return {
			sni: SNI,
			upstreams: [{ kind: 'tcp', host: '127.0.0.1', port }],
			terminateTls: false,
			failover: {
				peers: [{ host: '127.0.0.1', port: peer }],
				probeIntervalMs: 50,
				peerCooldownMs: { min: 200, max: 1000 },
			},
		};
	}

	it('keeps a Unix socket that accepts and closes out of rotation until it serves', async (t) => {
		const peer = await startPeer(t);
		const [a] = await allocatePorts(1);
		const nodeA = await startNode(t, a, { peers: [peer.node.ingressPort] });
		await markDown(nodeA);
		const health = recordHealth(nodeA.proxy);

		const closing = await startClosingUpstream(nodeA.socketPath);
		await waitFor(() => closing.accepted() >= 3);
		await assertServedByPeerOnly(nodeA, 0);
		assert.deepEqual(health, []);

		const up = routeHealth(nodeA.proxy, 'up');
		await closing.close();
		const upstreamA = await startUdsUpstream(nodeA.socketPath);
		t.after(() => upstreamA.close());
		await up;
		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(upstreamA.sources.length, 1, 'served locally');
		assert.equal(routeMetrics(nodeA).failover!.peers[0].forwarded, 3);
		assert.deepEqual(health, ['up']);
	});

	it('does not count a proxy in front of a refusing backend as up', async (t) => {
		const peer = await startPeer(t);
		const [a] = await allocatePorts(1);
		const port = await getFreePort();
		const backend = path.join(socketDir, `backend-${++socketSeq}.sock`);
		const nodeA = await startNode(t, a, {
			peers: [peer.node.ingressPort],
			passthrough: true,
			tcpUpstream: { host: '127.0.0.1', port },
		});
		assert.equal(await tryEcho({ port: a.publicPort }), 'ping', 'the published port refuses');

		const proxy = await startDockerProxy(t, port, backend);
		await waitFor(() => proxy.accepted() >= 3);
		await assertServedByPeerOnly(nodeA, 1);

		const up = routeHealth(nodeA.proxy, 'up');
		await startTlsUdsUpstream(t, backend);
		await up;
		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(routeMetrics(nodeA).failover!.peers[0].forwarded, 4, 'served locally');
	});

	it('keeps a down route down when a reload moves it onto a proxy already accepting', async (t) => {
		const peer = await startPeer(t);
		const [a] = await allocatePorts(1);
		const port = await getFreePort();
		const backend = path.join(socketDir, `backend-${++socketSeq}.sock`);
		const nodeA = await startNode(t, a, { peers: [peer.node.ingressPort] });
		await markDown(nodeA);
		const health = recordHealth(nodeA.proxy);
		const proxy = await startDockerProxy(t, port, backend);

		nodeA.proxy.updateConfig({ routes: [tcpRoute(port, peer.node.ingressPort)] });
		await waitFor(() => proxy.accepted() >= 3);
		await assertServedByPeerOnly(nodeA, 0);
		assert.deepEqual(health, [], 'no up at the reload');

		const up = routeHealth(nodeA.proxy, 'up');
		await startTlsUdsUpstream(t, backend);
		await up;
		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(routeMetrics(nodeA).failover!.peers[0].forwarded, 3, 'served locally');

		const upstreamA = await startUdsUpstream(nodeA.socketPath);
		t.after(() => upstreamA.close());
		nodeA.proxy.updateConfig({ routes: [nodeA.failoverRoute()] });
		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(upstreamA.sources.length, 1, 'back on the Unix socket');
		assert.deepEqual(health, ['up']);
	});

	it('does not report a replaced endpoint up for the route that replaced it', async (t) => {
		const peer = await startPeer(t);
		const [a] = await allocatePorts(1);
		const port = await getFreePort();
		const nodeA = await startNode(t, a, { peers: [peer.node.ingressPort] });
		await markDown(nodeA);
		const health = recordHealth(nodeA.proxy);
		await startDockerProxy(t, port, path.join(socketDir, `backend-${++socketSeq}.sock`));

		let accepted = false;
		const settling = net.createServer((socket) => {
			accepted = true;
			socket.on('error', () => {});
		});
		await new Promise<void>((resolve) => settling.listen(nodeA.socketPath, resolve));
		t.after(() => new Promise<void>((resolve) => settling.close(() => resolve())));
		await waitFor(() => accepted, 5000);
		nodeA.proxy.updateConfig({ routes: [tcpRoute(port, peer.node.ingressPort)] });

		await sleep(500);
		assert.deepEqual(health, []);
		assert.equal(routeMetrics(nodeA).failover!.localUp, false);
	});

	it('brings a down route up after a reload onto a healthy endpoint', async (t) => {
		const peer = await startPeer(t);
		const [a] = await allocatePorts(1);
		const nodeA = await startNode(t, a, { peers: [peer.node.ingressPort] });
		await markDown(nodeA);

		const healthyPath = path.join(socketDir, `healthy-${++socketSeq}.sock`);
		const healthy = await startUdsUpstream(healthyPath);
		t.after(() => healthy.close());
		const up = routeHealth(nodeA.proxy, 'up');
		nodeA.proxy.updateConfig({
			routes: [{ ...nodeA.failoverRoute(), upstreams: [{ kind: 'uds', path: healthyPath }] }],
		});
		await up;
		assert.equal(await tryEcho({ port: a.publicPort }), 'ping');
		assert.equal(healthy.sources.length, 1);
	});

	it('clears more endpoints than one batch of probes holds', async (t) => {
		const peer = await startPeer(t);
		const [a] = await allocatePorts(1);
		const paths = Array.from({ length: 65 }, () => path.join(socketDir, `slot-${++socketSeq}.sock`));
		const nodeA = await startNode(t, a, {
			routes: [
				{
					sni: SNI,
					upstreams: paths.map((socketPath) => ({ kind: 'uds' as const, path: socketPath })),
					terminateTls: true,
					cert: { certChain: cert, privateKey: key },
					failover: {
						peers: [{ host: '127.0.0.1', port: peer.node.ingressPort }],
						probeIntervalMs: 50,
						peerCooldownMs: { min: 200, max: 1000 },
					},
				},
			],
		});
		await markDown(nodeA);
		assert.equal(routeMetrics(nodeA).failover!.refusingSlots, 65);

		const upstreams = await Promise.all(paths.map((socketPath) => startUdsUpstream(socketPath)));
		t.after(() => Promise.all(upstreams.map((upstream) => upstream.close())));
		await waitFor(() => routeMetrics(nodeA).failover!.refusingSlots === 0);
	});

	it('keeps an upstream down while it closes idle connections sooner than the probe waits', async (t) => {
		const peer = await startPeer(t);
		const [a] = await allocatePorts(1);
		const nodeA = await startNode(t, a, { peers: [peer.node.ingressPort] });
		await markDown(nodeA);
		const closing = await startClosingUpstream(nodeA.socketPath, 50);
		t.after(() => closing.close());

		await waitFor(() => closing.accepted() >= 3);
		assert.equal(routeMetrics(nodeA).failover!.localUp, false);
	});

	it('cannot see a close later than the probe waits', async (t) => {
		const peer = await startPeer(t);
		const [a] = await allocatePorts(1);
		const nodeA = await startNode(t, a, { peers: [peer.node.ingressPort] });
		await markDown(nodeA);
		const up = routeHealth(nodeA.proxy, 'up');
		const closing = await startClosingUpstream(nodeA.socketPath, 1000);
		t.after(() => closing.close());
		await up;
	});
});

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
