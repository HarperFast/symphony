/**
 * Measures process RSS growth from parked connections — the memory curve issue #37 is about.
 * `tokio::io::copy_bidirectional`'s `CopyBuffer` allocates once and holds its buffer for the
 * connection's whole life, whether or not it is transferring; the fix (src/copy.rs) holds only a
 * small fixed floor while idle and escalates to the full `readBufferSize` only for the duration
 * of an actual sustained burst, so a parked connection (the MQTT shape: idle between publishes)
 * should cost a small fixed amount instead of `readBufferSize × 2` forever.
 *
 * Every connection sends one burst sized to `readBufferSize` (an MQTT PUBLISH shape: some
 * payload at least that large, at some point) before settling back to parked. This matters: a
 * read below the buffer's capacity only dirties the one page it actually writes into, so a
 * static buffer above the allocator's mmap threshold (glibc: 128 KiB) mostly sits on
 * lazily-faulted, never-touched pages regardless of whether the code holds it eagerly — that
 * would understate the OLD code's cost and make old-vs-new meaningless. Forcing a real burst
 * through is what makes the OLD static buffer become fully resident (and stay that way for the
 * connection's life) while the NEW buffer escalates for the burst and drops back down once
 * traffic quiets — demonstrating the actual point of the fix: resident memory should track
 * *peak concurrent transfers*, not total connection count or the configured maximum.
 *
 * TLS termination is used (matching __test__/copy-buffers.spec.ts) with an echoing TCP upstream
 * — the client's real TLS handshake terminates at symphony. rustls session state is an
 * unrelated, unchanged memory cost; the before/after delta on the same rig isolates the
 * copy-buffer question regardless.
 *
 * Not part of `npm test` — a manual measurement tool. Compare by running it against the base
 * commit (`tokio::io::copy_bidirectional_with_sizes`) and this branch; see the PR description
 * for the actual before/after numbers.
 *
 * Run with:
 *   npm run build:debug
 *   node --expose-gc dist-test/__test__/bench-copy-memory.js [connectionCount] [readBufferSize] [lazyCopyBufferThreshold]
 */
import * as tls from 'node:tls';
import { SymphonyProxy } from '../ts/proxy.js';
import { generateSelfSignedCert, getFreePort, startEchoServer, sleep } from './util.js';

const CONNECTIONS = Number(process.argv[2] ?? 30000);
// Deliberately large: the whole point of the fix is that a big configured buffer no longer
// means every idle connection pays for it. A small default would hide a regression.
const READ_BUFFER_SIZE = Number(process.argv[3] ?? 65536);
// Escalation is gated on active connections (src/copy.rs LazyBufferGate). 0 forces the escalating
// path whatever the connection count; pass a value above `connectionCount` to measure the static
// path — that pair is what isolates what the gate is actually buying.
const LAZY_THRESHOLD = Number(process.argv[4] ?? 0);
const BATCH = 250;

// A single loopback source address only has ~28k usable ephemeral ports
// (net.ipv4.ip_local_port_range), well under the connection counts this benchmark needs.
// Loopback supports the whole 127.0.0.0/8 range, so spreading client sockets across several
// source addresses multiplies the available (srcIP, srcPort) tuples instead.
const SOURCE_ADDRESSES = Array.from({ length: 16 }, (_, i) => `127.0.0.${i + 1}`);

function rssMb(): number {
	if (global.gc) global.gc();
	return process.memoryUsage().rss / (1024 * 1024);
}

async function main() {
	const cert = generateSelfSignedCert('localhost');
	// Idle upstream: accepts and holds the connection, never sends or expects data — the
	// "parked MQTT subscriber between publishes" shape this issue is about.
	const upstream = await startEchoServer();

	const proxyPort = await getFreePort();
	const proxy = new SymphonyProxy({
		listeners: [{ host: '127.0.0.1', port: proxyPort }],
		routes: [
			{
				sni: 'localhost',
				terminateTls: true,
				cert: { certChain: cert.cert, privateKey: cert.key },
				upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: upstream.port }],
			},
		],
		readBufferSize: READ_BUFFER_SIZE,
		lazyCopyBufferThreshold: LAZY_THRESHOLD,
	});
	await proxy.start();

	await sleep(200);
	const baselineMb = rssMb();
	console.log(`readBufferSize=${READ_BUFFER_SIZE}B/direction (${READ_BUFFER_SIZE * 2}B/connection if held permanently)`);
	console.log(`baseline RSS (proxy + upstream server, 0 connections): ${baselineMb.toFixed(1)} MiB`);

	const sockets: tls.TLSSocket[] = [];
	for (let i = 0; i < CONNECTIONS; i += BATCH) {
		const n = Math.min(BATCH, CONNECTIONS - i);
		const batchStart = Date.now();
		await Promise.all(
			Array.from({ length: n }, (_, j) => new Promise<void>((resolve, reject) => {
				const localAddress = SOURCE_ADDRESSES[(i + j) % SOURCE_ADDRESSES.length];
				const s = tls.connect(
					{ port: proxyPort, host: '127.0.0.1', servername: 'localhost', rejectUnauthorized: false, localAddress } as tls.ConnectionOptions,
					() => resolve(),
				);
				s.on('error', reject);
				// Keep flowing so the echoed burst (see below) actually drains instead of piling
				// up unread — a paused socket has no bearing on symphony's own memory, but an
				// unread echo sitting in the kernel receive buffer would stall the proxy's
				// upstream→client write, which would in turn distort the very thing under test.
				s.on('data', () => {});
				sockets.push(s);
			})),
		);
		console.log(`  connected ${i + n}/${CONNECTIONS} (batch took ${Date.now() - batchStart}ms)`);
	}
	console.log(`connected ${sockets.length} parked connections`);

	// One burst per connection sized to the configured buffer, fired in batches (no
	// per-connection acknowledgment tracking — with tens of thousands of sockets in one process,
	// thousands of individual listeners/timers is itself a source of event-loop pressure separate
	// from anything under test). This has to be at least `readBufferSize` bytes, not a single
	// byte: a read below the buffer's capacity only ever dirties the one page it actually writes
	// into, so a static buffer well above the allocator's mmap threshold (glibc: 128 KiB) mostly
	// sits on lazily-faulted, never-touched pages regardless of whether the code holds it
	// eagerly or not — that would understate the OLD code's cost and make the comparison
	// meaningless. Sized to the buffer, the burst forces the OLD static buffer to become fully
	// resident (matching a real client that at some point publishes a payload at least that
	// large), while the NEW code escalates for the burst and then drops back down once the
	// connection goes quiet again. A fixed settle period afterward gives the whole batch time to
	// round-trip through the echo upstream — see the file header for why this step (not just
	// connecting) is what makes the OLD/NEW difference observable in RSS. A handful of
	// connections not completing their round trip in time doesn't materially change a delta
	// computed across tens of thousands of connections.
	const burst = Buffer.alloc(READ_BUFFER_SIZE, 7);
	// Small on purpose: each write is up to `readBufferSize` (possibly 1 MiB), and this loop
	// waits for the kernel/TLS layer to actually accept it (backpressure-aware) before moving on
	// — a fire-and-forget write here would pile the unsent bytes up in *this test process's own*
	// write buffers, dwarfing anything happening on the symphony side and making the measurement
	// meaningless.
	const PING_BATCH = 200;
	let stalled = 0;
	for (let i = 0; i < sockets.length; i += PING_BATCH) {
		await Promise.all(
			sockets.slice(i, i + PING_BATCH).map((s) => new Promise<void>((resolve) => {
				// A per-write timeout backstop: at tens of thousands of sockets in one test
				// process a handful occasionally don't drain promptly (event-loop/socket
				// pressure in the test harness itself, reproduced identically against the base
				// commit — not a symphony behavior). Moving on rather than blocking the whole
				// batch keeps that noise from taking down the entire run.
				const timer = setTimeout(() => { stalled++; resolve(); }, 3000);
				if (s.write(burst)) { clearTimeout(timer); resolve(); }
				else s.once('drain', () => { clearTimeout(timer); resolve(); });
			})),
		);
		if ((i / PING_BATCH) % 10 === 0) console.log(`  burst-sent ${i + PING_BATCH}/${sockets.length}`);
	}
	console.log(`sent ${sockets.length} ${READ_BUFFER_SIZE}-byte bursts (${stalled} stalled past 3s and were skipped)`);

	// Let accept/handshake/ping bookkeeping settle so we're measuring steady-state idle, not
	// transient allocations.
	await sleep(5000);
	const loadedMb = rssMb();
	const deltaMb = loadedMb - baselineMb;
	const perConnBytes = (deltaMb * 1024 * 1024) / CONNECTIONS;

	console.log(`loaded RSS (${CONNECTIONS} parked connections): ${loadedMb.toFixed(1)} MiB`);
	console.log(`delta: ${deltaMb.toFixed(1)} MiB total, ${perConnBytes.toFixed(0)} bytes/connection`);

	// The numbers we care about are already printed; at tens of thousands of sockets a graceful
	// teardown (destroying each socket, waiting for the proxy/upstream to notice) is slow and
	// unnecessary for a one-shot measurement process, so exit immediately rather than hang here.
	process.exit(0);
}

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
