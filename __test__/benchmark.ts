/**
 * Benchmark: TLS termination overhead of Symphony vs direct Harper
 *
 * Compares latency of making simple GET requests directly to Harper
 * vs through Symphony → UDS → Harper, with a fresh TLS handshake per request.
 *
 * Run with:
 *   npm run build:debug
 *   npm run benchmark
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { request } from 'node:https';
import { parse } from 'yaml';
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
	if (existsSync(siblingBuild)) return siblingBuild;
	try {
		return join(require.resolve('harper'), '..', 'bin', 'harper.js');
	} catch {
		throw new Error(
			'Harper CLI not found. Set HARPER_INTEGRATION_TEST_INSTALL_SCRIPT or build harper-pro first.',
		);
	}
}

interface BenchmarkStats {
	name: string;
	latencies: number[];
	min: number;
	max: number;
	mean: number;
	median: number;
	p95: number;
	p99: number;
}

function percentile(arr: number[], p: number): number {
	const sorted = [...arr].sort((a, b) => a - b);
	const idx = Math.ceil((p / 100) * sorted.length) - 1;
	return sorted[Math.max(0, idx)];
}

function analyzeLatencies(name: string, latencies: number[]): BenchmarkStats {
	const sorted = [...latencies].sort((a, b) => a - b);
	return {
		name,
		latencies,
		min: sorted[0],
		max: sorted[sorted.length - 1],
		mean: latencies.reduce((a, b) => a + b, 0) / latencies.length,
		median: percentile(latencies, 50),
		p95: percentile(latencies, 95),
		p99: percentile(latencies, 99),
	};
}

function makeRequest(
	hostname: string,
	port: number,
	sni: string,
	ca: string,
): Promise<number> {
	return new Promise((resolve, reject) => {
		const startTime = Date.now();
		const req = request(
			{
				hostname,
				port,
				path: '/benchmark',
				method: 'GET',
				servername: sni,
				ca,
				headers: { Host: sni },
			},
			(res) => {
				res.resume(); // drain response body
				res.on('end', () => {
					const elapsed = Date.now() - startTime;
					resolve(elapsed);
				});
			},
		);
		req.on('error', reject);
		req.end();
	});
}

async function main() {
	const harperBinPath = process.env.HARPER_INTEGRATION_TEST_INSTALL_SCRIPT
		? undefined
		: resolveHarperBin();

	console.log('Starting Harper (with TCP + UDS TLS)...');
	const harperCtx = await startHarper(createHarperContext('symphony-benchmark'), {
		harperBinPath,
		config: {
			tls: { unixDomainSockets: true, tcp: true },
			threads: { count: 2 },
		},
	});

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

	const upstreams = yamlFiles.map((yamlFile) => ({
		kind: 'uds' as const,
		path: join(socketsDir, yamlFile.replace('.yaml', '.sock')),
	}));

	const portStr = String(metadataList[0].port);
	const harperPort = portStr.includes(':') ? parseInt(portStr.split(':').pop()!, 10) : parseInt(portStr, 10);

	const sniHostname =
		(cert.hostnames as string[]).find((h) => !/^[\d.:]+$/.test(h)) || cert.hostnames[0];

	const caCert = (cert.certificateAuthorities as string[] | undefined)?.join('\n') ?? cert.certificate;

	// Extract Harper's actual listening hostname from httpURL
	// Format: https://127.0.0.X:YYYY/
	const harperURL = new URL(harperCtx.harper.httpURL);
	const harperDirectHost = harperURL.hostname;

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

	// Wait a bit for Harper to be fully ready
	await new Promise((r) => setTimeout(r, 500));

	// Warmup
	console.log('\nWarming up...');
	try {
		await makeRequest(harperDirectHost, harperPort, sniHostname, caCert);
		console.log('✓ Direct Harper request warmed up');
	} catch (err) {
		console.error('✗ Direct warmup failed:', (err as Error).message);
		throw err;
	}

	try {
		await makeRequest(symphonyHost, symphonyPort, sniHostname, caCert);
		console.log('✓ Symphony request warmed up');
	} catch (err) {
		console.error('✗ Symphony warmup failed:', (err as Error).message);
		throw err;
	}

	// Run benchmarks
	const requestCount = 500;
	console.log(`\nRunning benchmark (${requestCount} requests each)...\n`);

	console.log(`Making direct requests to Harper (${harperDirectHost}:${harperPort})...`);
	const directLatencies: number[] = [];
	for (let i = 0; i < requestCount; i++) {
		try {
			const latency = await makeRequest(harperDirectHost, harperPort, sniHostname, caCert);
			directLatencies.push(latency);
			if ((i + 1) % 10 === 0) {
				process.stdout.write(`  ${i + 1}/${requestCount}\r`);
			}
		} catch (err) {
			console.error(`\nDirect request ${i} failed:`, (err as Error).message);
		}
	}
	console.log('');

	console.log(`Making requests through Symphony → Harper (via UDS) (${symphonyHost}:${symphonyPort})...`);
	const symphonyLatencies: number[] = [];
	for (let i = 0; i < requestCount; i++) {
		try {
			const latency = await makeRequest(symphonyHost, symphonyPort, sniHostname, caCert);
			symphonyLatencies.push(latency);
			if ((i + 1) % 10 === 0) {
				process.stdout.write(`  ${i + 1}/${requestCount}\r`);
			}
		} catch (err) {
			console.error(`\nSymphony request ${i} failed:`, (err as Error).message);
		}
	}
	console.log('');

	// Analyze and report
	if (directLatencies.length === 0 || symphonyLatencies.length === 0) {
		console.error(
			'\n✗ Benchmark failed: insufficient successful requests',
			`(direct: ${directLatencies.length}, symphony: ${symphonyLatencies.length})`,
		);
		process.exit(1);
	}

	const directStats = analyzeLatencies('Direct Harper', directLatencies);
	const symphonyStats = analyzeLatencies('Symphony → Harper', symphonyLatencies);

	console.log('\n=== Results ===\n');
	console.log(`Direct Harper (baseline) — ${directLatencies.length} samples:`);
	console.log(`  Mean:   ${directStats.mean.toFixed(1)}ms`);
	console.log(`  Median: ${directStats.median.toFixed(1)}ms`);
	console.log(`  Min:    ${directStats.min.toFixed(1)}ms`);
	console.log(`  Max:    ${directStats.max.toFixed(1)}ms`);
	console.log(`  p95:    ${directStats.p95.toFixed(1)}ms`);
	console.log(`  p99:    ${directStats.p99.toFixed(1)}ms`);

	console.log(`\nSymphony → Harper (via UDS) — ${symphonyLatencies.length} samples:`);
	console.log(`  Mean:   ${symphonyStats.mean.toFixed(1)}ms`);
	console.log(`  Median: ${symphonyStats.median.toFixed(1)}ms`);
	console.log(`  Min:    ${symphonyStats.min.toFixed(1)}ms`);
	console.log(`  Max:    ${symphonyStats.max.toFixed(1)}ms`);
	console.log(`  p95:    ${symphonyStats.p95.toFixed(1)}ms`);
	console.log(`  p99:    ${symphonyStats.p99.toFixed(1)}ms`);

	const meanOverhead = symphonyStats.mean - directStats.mean;
	const medianOverhead = symphonyStats.median - directStats.median;
	const pctOverhead = ((meanOverhead / directStats.mean) * 100).toFixed(1);

	console.log('\nTLS Termination Overhead (Symphony - Direct):');
	console.log(`  Mean:   ${meanOverhead.toFixed(1)}ms (${pctOverhead}%)`);
	console.log(`  Median: ${medianOverhead.toFixed(1)}ms`);

	// Cleanup
	console.log('\nCleaning up...');
	await proxy.stop(1000).catch(() => {});
	await teardownHarper(harperCtx).catch(() => {});
	releaseLoopbackAddress(symphonyHost);

	console.log('Done.');
	process.exit(0);
}

main().catch((err) => {
	console.error('Benchmark failed:', err);
	process.exit(1);
});
