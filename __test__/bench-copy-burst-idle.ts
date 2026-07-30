/**
 * Repeated burst/idle cycles per connection — the workload the acceptance criteria describes
 * (MQTT fan-out: connections that burst, go quiet, then burst again) and the one shape neither
 * bench-copy-memory (one burst, then quiet forever) nor bench-copy-throughput (one sustained
 * burst) exercises. Reviewer ask on PR #41: the design's escalate -> park -> shrink ->
 * re-escalate mechanism costs two allocations plus a zeroing `vec![0u8; n]` per direction per
 * cycle (src/copy.rs) — this is the only benchmark where that churn sits on the hot path, so
 * it's the one that can actually show whether the cost is as negligible as the module docs
 * argue, by reporting both throughput and RSS across many repeated cycles instead of a single
 * before/after snapshot.
 *
 * Every connection, each cycle: write a `readBufferSize`-sized burst, wait for the full echo
 * back, then sleep `idleMs` — long enough for both directions to actually park and shrink (see
 * src/copy.rs's shrink-on-park design) before the next cycle's burst starts. All connections run
 * each cycle in lockstep so RSS can be sampled between cycles: a flat curve across cycles means
 * the per-cycle churn isn't accumulating; a climbing one would mean it is.
 *
 * Not part of `npm test` — a manual measurement tool. Compare by running it against the base
 * commit (`tokio::io::copy_bidirectional_with_sizes`) and this branch.
 *
 * Run with:
 *   npm run build:debug
 *   node --expose-gc dist-test/__test__/bench-copy-burst-idle.js [connections] [readBufferSize] [cycles] [idleMs] [lazyCopyBufferThreshold]
 */
import * as tls from 'node:tls';
import { SymphonyProxy } from '../ts/proxy.js';
import { generateSelfSignedCert, getFreePort, startEchoServer, sleep } from './util.js';

const CONNECTIONS = Number(process.argv[2] ?? 2000);
const READ_BUFFER_SIZE = Number(process.argv[3] ?? 65536);
const CYCLES = Number(process.argv[4] ?? 15);
const IDLE_MS = Number(process.argv[5] ?? 250);
// Escalation is gated on active connections (see src/copy.rs LazyBufferGate). Pinned to 0 by
// default so the benchmark measures the escalating path whatever connection count it is given;
// pass a value above `connections` to measure the static path for comparison.
const LAZY_THRESHOLD = Number(process.argv[6] ?? 0);
const CONNECT_BATCH = 250;

// See bench-copy-memory.ts: spreading client sockets across several loopback source addresses
// avoids exhausting the ~28k usable ephemeral ports on a single source address.
const SOURCE_ADDRESSES = Array.from({ length: 16 }, (_, i) => `127.0.0.${i + 1}`);

function rssMb(): number {
	if (global.gc) global.gc();
	return process.memoryUsage().rss / (1024 * 1024);
}

async function main() {
	const cert = generateSelfSignedCert('localhost');
	// A real echo, not a sink: each cycle's burst has to actually round-trip so the connection
	// goes genuinely idle (nothing left to write on either side) before the next cycle — that's
	// the "park" condition src/copy.rs shrinks on, and the whole point of this benchmark is to
	// exercise that transition repeatedly rather than once.
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

	console.log(`connections=${CONNECTIONS} readBufferSize=${READ_BUFFER_SIZE}B cycles=${CYCLES} idleMs=${IDLE_MS}`);

	const sockets: tls.TLSSocket[] = [];
	for (let i = 0; i < CONNECTIONS; i += CONNECT_BATCH) {
		const n = Math.min(CONNECT_BATCH, CONNECTIONS - i);
		const batchStart = Date.now();
		await Promise.all(
			Array.from({ length: n }, (_, j) => new Promise<void>((resolve, reject) => {
				const localAddress = SOURCE_ADDRESSES[(i + j) % SOURCE_ADDRESSES.length];
				const s = tls.connect(
					{ port: proxyPort, host: '127.0.0.1', servername: 'localhost', rejectUnauthorized: false, localAddress } as tls.ConnectionOptions,
					() => resolve(),
				);
				s.on('error', reject);
				sockets.push(s);
			})),
		);
		console.log(`  connected ${i + n}/${CONNECTIONS} (batch took ${Date.now() - batchStart}ms)`);
	}
	console.log(`connected ${sockets.length} connections`);

	await sleep(200);
	const baselineMb = rssMb();
	console.log(`baseline RSS (connected, before first burst): ${baselineMb.toFixed(1)} MiB`);

	const burst = Buffer.alloc(READ_BUFFER_SIZE, 7);
	let totalBytes = 0;
	const start = Date.now();
	const rssSamples: number[] = [];

	for (let cycle = 0; cycle < CYCLES; cycle++) {
		await Promise.all(
			sockets.map((s) => new Promise<void>((resolve) => {
				let received = 0;
				const cleanup = () => {
					s.off('data', onData);
					s.off('error', onDone);
					s.off('close', onDone);
					resolve();
				};
				const onData = (chunk: Buffer) => {
					received += chunk.length;
					if (received >= burst.length) cleanup();
				};
				// A socket that errors or closes mid-cycle (loopback flakiness at thousands of
				// connections) must still resolve this promise — otherwise that one socket's
				// `Promise.all` never settles and the whole run wedges with no diagnostic.
				const onDone = () => cleanup();
				s.on('data', onData);
				s.once('error', onDone);
				s.once('close', onDone);
				s.write(burst);
			})),
		);
		totalBytes += burst.length * sockets.length * 2; // client->upstream and upstream->client

		// Long enough for both copy directions to actually park (see src/copy.rs's
		// shrink-on-park design) before the next cycle's burst — this is what makes the
		// escalate/shrink churn under test happen at all; too short a gap would just look like
		// one continuing sustained burst and never trigger a shrink.
		await sleep(IDLE_MS);
		const sampleMb = rssMb();
		rssSamples.push(sampleMb);
		console.log(`  cycle ${cycle + 1}/${CYCLES}: RSS ${sampleMb.toFixed(1)} MiB`);
	}

	const elapsedS = (Date.now() - start) / 1000;
	const mibps = totalBytes / (1024 * 1024) / elapsedS;
	const minRss = Math.min(...rssSamples);
	const maxRss = Math.max(...rssSamples);

	console.log(
		`throughput: ${mibps.toFixed(1)} MiB/s over ${elapsedS.toFixed(1)}s ` +
		`(${CYCLES} burst/idle cycles x ${sockets.length} connections, both directions)`,
	);
	console.log(
		`RSS across cycles: min ${minRss.toFixed(1)} MiB, max ${maxRss.toFixed(1)} MiB, ` +
		`baseline ${baselineMb.toFixed(1)} MiB, peak delta from baseline ${(maxRss - baselineMb).toFixed(1)} MiB`,
	);
	console.log('A flat RSS curve across cycles (no upward trend from the first sample to the last) means the escalate/park/shrink churn is not accumulating.');

	// See bench-copy-memory.ts: a graceful teardown of thousands of sockets is slow and
	// unnecessary for a one-shot measurement process.
	process.exit(0);
}

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
