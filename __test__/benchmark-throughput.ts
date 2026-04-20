/**
 * Throughput benchmark: Maximum requests/sec with concurrency
 *
 * Compares throughput of direct Harper vs Symphony with various concurrency levels.
 *
 * Run with:
 *   npm run build:debug
 *   npm run benchmark:throughput
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { request } from 'node:https';
import { parse } from 'yaml';
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads';
import { availableParallelism } from 'node:os';
import {
	createHarperContext,
	startHarper,
	teardownHarper,
	getNextAvailableLoopbackAddress,
	releaseLoopbackAddress,
	type StartedHarperTestContext,
} from '@harperfast/integration-testing';
import { SymphonyProxy } from '../ts/proxy.js';

function resolveHarperBin(): string {
	const siblingBuild = join(__dirname, '..', '..', '..', 'harper-pro', 'dist', 'bin', 'harper.js');
	console.log('sibling build', siblingBuild);
	if (existsSync(siblingBuild)) return siblingBuild;
	try {
		return join(require.resolve('harper'), '..', 'bin', 'harper.js');
	} catch {
		throw new Error(
			'Harper CLI not found. Set HARPER_INTEGRATION_TEST_INSTALL_SCRIPT or build harper-pro first.',
		);
	}
}

const REQUEST_TIMEOUT_MS = 5000;

function makeRequest(
	hostname: string,
	port: number,
	sni: string,
	ca: string,
): Promise<void> {
	return new Promise((resolve, reject) => {
		const req = request(
			{
				agent: false,
				hostname,
				port,
				path: '/benchmark',
				method: 'GET',
				servername: sni,
				//ca,
				rejectUnauthorized: false,
				headers: { Host: sni },
				timeout: REQUEST_TIMEOUT_MS,
			},
			(res) => {
				res.resume(); // drain response body
				res.on('end', () => resolve());
			},
		);
		req.on('timeout', () => {
			req.destroy(new Error(`timeout after ${REQUEST_TIMEOUT_MS}ms`));
		});
		req.on('error', reject);
		req.end();
	});
}

interface ThroughputResult {
	rps: number;
	errors: number;
	total: number;
	errorSamples: string[];
}

// Number of worker threads to use for the benchmark client.
// Defaults to half the available CPU count, minimum 2, to leave headroom for
// the server processes (Harper, Symphony) running on the same machine.
const CLIENT_THREADS = Math.max(2, Math.floor(availableParallelism() / 2));

// Per-thread concurrency. Total in-flight connections = CLIENT_THREADS × PER_THREAD_CONCURRENCY.
function perThreadConcurrency(totalConcurrency: number): number {
	return Math.max(1, Math.ceil(totalConcurrency / CLIENT_THREADS));
}

async function measureThroughput(
	hostname: string,
	port: number,
	sni: string,
	ca: string,
	concurrency: number,
	durationMs: number,
): Promise<ThroughputResult> {
	let successCount = 0;
	let errorCount = 0;
	const errorSamples: string[] = [];
	let running = true;

	// Each coroutine fires requests back-to-back with no delay,
	// keeping exactly `concurrency` requests in-flight at all times.
	async function coroutine(): Promise<void> {
		while (running) {
			try {
				await makeRequest(hostname, port, sni, ca);
				successCount++;
			} catch (err) {
				errorCount++;
				if (errorSamples.length < 3) {
					errorSamples.push((err as Error).message);
				}
			}
		}
	}

	const coroutines = Array.from({ length: concurrency }, () => coroutine());
	const timer = setTimeout(() => { running = false; }, durationMs);
	const startTime = Date.now();
	await Promise.all(coroutines);
	clearTimeout(timer);

	const elapsedMs = Date.now() - startTime;
	const total = successCount + errorCount;
	return {
		rps: (successCount / elapsedMs) * 1000,
		errors: errorCount,
		total,
		errorSamples,
	};
}

// Spawn CLIENT_THREADS worker threads each running measureThroughput with
// perThreadConcurrency(concurrency) coroutines, then aggregate their results.
// Total in-flight connections ≈ concurrency; client-side crypto is parallelised
// across threads so a single event loop can no longer bottleneck the server.
function measureThroughputMultiThreaded(
	hostname: string,
	port: number,
	sni: string,
	ca: string,
	concurrency: number,
	durationMs: number,
): Promise<ThroughputResult> {
	const perThread = perThreadConcurrency(concurrency);
	const workers: Promise<ThroughputResult>[] = Array.from({ length: CLIENT_THREADS }, () =>
		new Promise<ThroughputResult>((resolve, reject) => {
			const w = new Worker(__filename, {
				workerData: { hostname, port, sni, ca, concurrency: perThread, durationMs },
			});
			w.once('message', resolve);
			w.once('error', reject);
		})
	);
	return Promise.all(workers).then((results) => {
		const combined: ThroughputResult = { rps: 0, errors: 0, total: 0, errorSamples: [] };
		for (const r of results) {
			combined.rps += r.rps;
			combined.errors += r.errors;
			combined.total += r.total;
			if (combined.errorSamples.length < 3) {
				combined.errorSamples.push(...r.errorSamples.slice(0, 3 - combined.errorSamples.length));
			}
		}
		return combined;
	});
}

async function main() {
	const harperBinPath = process.env.HARPER_INTEGRATION_TEST_INSTALL_SCRIPT
		? undefined
		: resolveHarperBin();

	console.log('Starting Harper (with TCP + UDS TLS)...');
	const harperCtx = await startHarper(createHarperContext('symphony-benchmark-throughput'), {
		harperBinPath,
		config: {
			tls: {
				unixDomainSockets: true,
				//privateKey: '/tmp/privkey.pem',
				//certificate: '/tmp/fullchain.pem',
			},
			threads: { count: 6 },
			logging: {
				level: 'debug',
			}
		},
	});
	console.log('data root dir', harperCtx.harper.dataRootDir);
	const socketsDir = join(harperCtx.harper.dataRootDir, 'sockets');

	// Poll for UDS metadata YAML files
	console.log('Waiting for UDS metadata files...');
	let yamlFiles: string[] = [];
	for (let attempt = 0; attempt < 60; attempt++) {
		try {
			yamlFiles = readdirSync(socketsDir).filter((f) => f.endsWith('.yaml'));
			if (yamlFiles.length > 0) break;
		} catch {
			// directory may not exist yet
		}
		await new Promise((r) => setTimeout(r, 500));
	}

	if (yamlFiles.length === 0) {
		throw new Error(`No UDS metadata files found in ${socketsDir}`);
	}

	// Parse metadata
	const metadataList = yamlFiles.map((f) => parse(readFileSync(join(socketsDir, f), 'utf8')));
	const cert = metadataList[0].certificates[0];
	if (!cert) throw new Error('No certificate in metadata');

	let upstreams = yamlFiles.map((yamlFile) => ({
		kind: 'uds' as const,
		path: join(socketsDir, yamlFile.replace('.yaml', '.sock')),
	}));


	const portStr = String(metadataList[0].port);
	const harperPort = portStr.includes(':') ? parseInt(portStr.split(':').pop()!, 10) : parseInt(portStr, 10);

	const sniHostname =
		(cert.hostnames as string[]).find((h) => !/^[\d.:]+$/.test(h)) || cert.hostnames[0];

	const caCert = (cert.certificateAuthorities as string[] | undefined)?.join('\n') ?? cert.certificate;

	// Extract Harper's actual listening hostname from httpURL
	const harperURL = new URL(harperCtx.harper.httpURL);
	const harperDirectHost = harperURL.hostname;
	upstreams = upstreams.filter((u) => u.path.includes(harperDirectHost));

	// Can you use this to test non TLS proxying
	/*const upstreams = [
		{ kind: 'tcp' as const, host: harperDirectHost, port: harperPort },
	];*/

	console.log(`Harper listening on ${harperDirectHost}:${harperPort} (TLS, direct)`);
	console.log(`SNI hostname: ${sniHostname}`);

	// Setup Symphony
	console.log('Starting Symphony...');
	const symphonyHost = await getNextAvailableLoopbackAddress();
	const symphonyPort = harperPort;

	const proxy = new SymphonyProxy({
		listeners: [{ host: symphonyHost, port: symphonyPort }],
		routes: [
			{
				sni: sniHostname,
				upstreams,
				terminateTls: true,
				cert: {
					certChain: cert.certificate as string,
					privateKey: readFileSync(cert.privateKeyFile as string, 'utf8'),
				},
			},
		],
	});

	await proxy.start();
	console.log(`Symphony listening on ${symphonyHost}:${symphonyPort}`);

	// Wait for services to stabilize
	await new Promise((r) => setTimeout(r, 500));

	// Warmup
	console.log('\nWarming up...');
	try {
		await makeRequest(harperDirectHost, harperPort, sniHostname, caCert);
		console.log('✓ Direct Harper warmed up');
	} catch (err) {
		console.error('✗ Direct warmup failed:', (err as Error).message);
		throw err;
	}

	try {
		await makeRequest(symphonyHost, symphonyPort, sniHostname, caCert);
		console.log('✓ Symphony warmed up');
	} catch (err) {
		console.error('✗ Symphony warmup failed:', (err as Error).message);
		throw err;
	}

	// Run throughput benchmarks
	const concurrencyLevels = [1, 10, 50, 100, 200];
	const durationMs = 5000;

	console.log(`\nRunning throughput benchmarks (${durationMs}ms per level, ${CLIENT_THREADS} client threads)...\n`);
	console.log('Concurrency | Direct (req/s) | Symphony (req/s) | Overhead | Sym errors');
	console.log('------------|----------------|------------------|----------|----------');

	for (const concurrency of concurrencyLevels) {
		process.stdout.write(`  c=${concurrency}: measuring direct...  \r`);
		const direct = await measureThroughputMultiThreaded(harperDirectHost, harperPort, sniHostname, caCert, concurrency, durationMs);

		process.stdout.write(`  c=${concurrency}: measuring symphony...\r`);
		const sym = await measureThroughputMultiThreaded(symphonyHost, symphonyPort, sniHostname, caCert, concurrency, durationMs);

		const overhead = direct.rps > 0 ? ((direct.rps - sym.rps) / direct.rps * 100).toFixed(1) + '%' : 'N/A';
		const errNote = sym.errors > 0 ? `${sym.errors}/${sym.total}` : '0';

		console.log(
			`${String(concurrency).padEnd(12)}| ` +
			`${direct.rps.toFixed(0).padEnd(16)}| ` +
			`${sym.rps.toFixed(0).padEnd(18)}| ` +
			`${overhead.padEnd(10)}| ${errNote}`,
		);
		if (sym.errorSamples.length > 0) {
			console.log(`  Error samples: ${sym.errorSamples.join('; ')}`);
		}
	}

	// Cleanup
	console.log('\nCleaning up...');
	await proxy.stop(1000).catch(() => {});
	await teardownHarper(harperCtx).catch(() => {});
	releaseLoopbackAddress(symphonyHost);

	console.log('Done.');
	process.exit(0);
}

// ── Worker thread entrypoint ─────────────────────────────────────────────────
// When spawned as a worker, run measureThroughput and post results back.
if (!isMainThread) {
	const { hostname, port, sni, ca, concurrency, durationMs } = workerData as {
		hostname: string;
		port: number;
		sni: string;
		ca: string;
		concurrency: number;
		durationMs: number;
	};
	measureThroughput(hostname, port, sni, ca, concurrency, durationMs).then((result) => {
		parentPort!.postMessage(result);
	});
} else {
	main().catch((err) => {
		console.error('Benchmark failed:', err);
		process.exit(1);
	});
}
