/**
 * Bulk throughput check for issue #37: a few connections pushing sustained high-volume data
 * through the copy loop — the replication profile on port 9933 (few connections, high volume),
 * the opposite shape from the many-parked-MQTT-subscribers case the memory fix targets. The
 * lazy/released buffer in src/copy.rs must not cost throughput on this path relative to
 * `tokio::io::copy_bidirectional_with_sizes`.
 *
 * TLS termination (matching __test__/copy-buffers.spec.ts) with a plain TCP sink upstream —
 * client→upstream is the direction under measurement.
 *
 * Not part of `npm test` — a manual measurement tool. Compare by running it against the base
 * commit and this branch; see the PR description for the actual before/after numbers.
 *
 * Run with:
 *   npm run build:debug
 *   node dist-test/__test__/bench-copy-throughput.js [connections] [durationMs]
 */
import * as net from 'node:net';
import * as tls from 'node:tls';
import { SymphonyProxy } from '../ts/proxy.js';
import { generateSelfSignedCert, getFreePort } from './util.js';

const CONNECTIONS = Number(process.argv[2] ?? 4);
const DURATION_MS = Number(process.argv[3] ?? 8000);
const CHUNK_SIZE = 256 * 1024;

async function main() {
	const cert = generateSelfSignedCert('localhost');
	let totalReceived = 0;
	const upstreamPort = await getFreePort();
	// Sink: reads and discards, so the client→upstream direction is the one under measurement
	// (matches a replication log-shipping / bulk-write shape).
	const upstream = net.createServer((socket) => {
		socket.on('data', (chunk: Buffer) => {
			totalReceived += chunk.length;
		});
		socket.on('error', () => {});
	});
	await new Promise<void>((resolve) => upstream.listen(upstreamPort, '127.0.0.1', resolve));

	const proxyPort = await getFreePort();
	const proxy = new SymphonyProxy({
		listeners: [{ host: '127.0.0.1', port: proxyPort }],
		routes: [
			{
				sni: 'localhost',
				terminateTls: true,
				cert: { certChain: cert.cert, privateKey: cert.key },
				upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: upstreamPort }],
			},
		],
	});
	await proxy.start();

	const chunk = Buffer.alloc(CHUNK_SIZE, 7);
	const sockets: tls.TLSSocket[] = [];
	await Promise.all(
		Array.from({ length: CONNECTIONS }, () => new Promise<void>((resolve, reject) => {
			const s = tls.connect(
				{ port: proxyPort, host: '127.0.0.1', servername: 'localhost', rejectUnauthorized: false },
				() => resolve(),
			);
			s.on('error', reject);
			sockets.push(s);
		})),
	);

	function pump(socket: tls.TLSSocket) {
		function write() {
			let ok = true;
			while (ok) ok = socket.write(chunk);
		}
		socket.on('drain', write);
		write();
	}

	const start = Date.now();
	for (const s of sockets) pump(s);
	await new Promise((r) => setTimeout(r, DURATION_MS));
	const elapsedS = (Date.now() - start) / 1000;

	const mibps = totalReceived / (1024 * 1024) / elapsedS;
	console.log(
		`connections=${CONNECTIONS} duration=${elapsedS.toFixed(1)}s ` +
		`received=${(totalReceived / 1024 / 1024).toFixed(1)}MiB throughput=${mibps.toFixed(1)} MiB/s`,
	);

	for (const s of sockets) s.destroy();
	await proxy.stop(1000).catch(() => {});
	await new Promise<void>((resolve) => upstream.close(() => resolve()));
	process.exit(0);
}

main().catch((err) => {
	console.error(err);
	process.exit(1);
});
