/**
 * Integration test: symphony UDS proxy → Harper
 *
 * Starts a real Harper instance with TLS and unix domain socket mirroring enabled,
 * reads the per-thread UDS metadata YAML files Harper writes, configures a
 * SymphonyProxy from that metadata, then sends HTTPS requests through symphony
 * (TLS termination) → UDS → Harper and asserts valid HTTP responses.
 *
 * Requires the native addon to be built:
 *   npm run build:debug
 *
 * The `harper` npm package is resolved automatically by @harperfast/integration-testing.
 */

import { suite, test, before, after, type TestContext } from 'node:test';
import { equal, ok } from 'node:assert';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { request } from 'node:https';
import { connect as connectTcp } from 'node:net';
import { connect as connectTls, type TLSSocket } from 'node:tls';
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
import type { ProtectionConfig, RouteConfig } from '../ts/types.js';
import { clientHello, getFreePort, sleep, startSlowRelay } from './util.js';

// Resolve the harper CLI script path.
// Priority:
//   1. HARPER_INTEGRATION_TEST_INSTALL_SCRIPT env var (set in CI)
//   2. Sibling workspace build: ../harper-pro/dist/bin/harper.js (local development)
//   3. harper npm package dist/bin/harper.js (fallback if installed and up-to-date)
function resolveHarperBin(): string {
	// env var is handled by @harperfast/integration-testing internally, skip here
	// use the sibling workspace build as the primary local dev fallback
	const siblingBuild = join(__dirname, '..', '..', '..', 'harper-pro', 'dist', 'bin', 'harper.js');
	if (existsSync(siblingBuild)) return siblingBuild;
	// fallback: harper npm package compiled output
	try {
		return join(require.resolve('harper'), '..', 'bin', 'harper.js');
	} catch {
		throw new Error(
			'Harper CLI not found. Set HARPER_INTEGRATION_TEST_INSTALL_SCRIPT or build harper-pro first.',
		);
	}
}
// Only resolve harperBinPath when env var is not already set (integration-testing uses it directly)
const harperBinPath = process.env.HARPER_INTEGRATION_TEST_INSTALL_SCRIPT
	? undefined
	: resolveHarperBin();

suite('Symphony UDS proxy – Harper integration', () => {
	let harperCtx: StartedHarperTestContext;
	let proxy: SymphonyProxy;
	let symphonyHost: string;
	let requestPort: number;
	let sniHostname: string;
	let caCert: string;
	let route: RouteConfig;

	/** A route that connects to Harper before its handshake. Its one peer refuses, so only Harper can serve it. */
	async function startFailoverProxy(t: TestContext, protection?: ProtectionConfig) {
		const port = await getFreePort();
		const failoverProxy = new SymphonyProxy({
			listeners: [{ host: symphonyHost, port, protection }],
			routes: [{ ...route, failover: { peers: [{ host: '127.0.0.1', port: await getFreePort() }] } }],
		});
		await failoverProxy.start();
		t.after(() => failoverProxy.stop(1000));
		return { port, proxy: failoverProxy };
	}

	function httpStatus(socket: TLSSocket): Promise<number> {
		return new Promise((resolve, reject) => {
			let response = '';
			socket.on('secureConnect', () =>
				socket.write(`GET / HTTP/1.1\r\nHost: ${sniHostname}\r\nConnection: close\r\n\r\n`)
			);
			socket.on('data', (chunk: Buffer) => {
				response += chunk.toString();
				const status = /^HTTP\/1\.1 (\d+)/.exec(response);
				if (status) {
					socket.destroy();
					resolve(Number(status[1]));
				}
			});
			socket.on('error', reject);
			socket.on('close', () => reject(new Error(`closed after ${JSON.stringify(response)}`)));
		});
	}

	function errorCount(failoverProxy: SymphonyProxy, reason: string): number {
		const metrics = failoverProxy.metrics().routeMetrics.find((r) => r.route === sniHostname)!;
		return metrics.errorsByReason.find((c) => c.reason === reason)?.count ?? 0;
	}

	before(async () => {
		harperCtx = await startHarper(createHarperContext('symphony-uds-proxy'), {
			harperBinPath,
			config: {
				tls: { unixDomainSockets: true },
				threads: { count: 2 },
			},
		});

		const socketsDir = join(harperCtx.harper.dataRootDir, 'sockets');

		// Poll for UDS metadata YAML files (written asynchronously after TLS init)
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
		ok(yamlFiles.length > 0, `Expected UDS metadata files in ${socketsDir}`);

		// Parse all YAML metadata files
		const metadataList = yamlFiles.map((f) => parse(readFileSync(join(socketsDir, f), 'utf8')));
		const cert = metadataList[0].certificates[0];
		ok(cert, 'Expected at least one certificate in UDS metadata');

		// Build symphony upstreams from each thread's UDS socket
		const upstreams = yamlFiles.map((yamlFile) => ({
			kind: 'uds' as const,
			path: join(socketsDir, yamlFile.replace('.yaml', '.sock')),
		}));

		// Extract numeric port (metadata may store "host:port" or a plain number)
		const portStr = String(metadataList[0].port);
		requestPort = portStr.includes(':') ? parseInt(portStr.split(':').pop()!, 10) : parseInt(portStr, 10);

		// Prefer a non-IP hostname for SNI so the cert validates
		sniHostname =
			(cert.hostnames as string[]).find((h) => !/^[\d.:]+$/.test(h)) || cert.hostnames[0];

		// CA cert for trusting the self-signed chain
		caCert = (cert.certificateAuthorities as string[] | undefined)?.join('\n') ?? cert.certificate;

		// Acquire a dedicated loopback address for symphony to listen on
		symphonyHost = await getNextAvailableLoopbackAddress();

		route = {
			sni: sniHostname,
			upstreams,
			terminateTls: true,
			cert: {
				certChain: cert.certificate as string,
				privateKey: readFileSync(cert.privateKeyFile as string, 'utf8'),
			},
		};
		proxy = new SymphonyProxy({
			listeners: [{ host: symphonyHost, port: requestPort }],
			routes: [route],
		});

		await proxy.start();
	});

	after(async () => {
		if (proxy) await proxy.stop(1000).catch(() => {});
		await teardownHarper(harperCtx).catch(() => {});
		if (symphonyHost) releaseLoopbackAddress(symphonyHost);
	});

	test('request proxied through symphony via UDS returns a response from Harper', async () => {
		const response = await new Promise<{ status: number; body: string }>((resolve, reject) => {
			const req = request(
				{
					hostname: symphonyHost,
					port: requestPort,
					path: '/',
					method: 'GET',
					servername: sniHostname,
					ca: caCert,
					headers: { Host: sniHostname },
				},
				(res) => {
					let body = '';
					res.on('data', (chunk) => (body += chunk));
					res.on('end', () => resolve({ status: res.statusCode!, body }));
				},
			);
			req.on('error', reject);
			req.end();
		});

		// With no applications deployed, Harper responds 404 or 400.
		// Any HTTP response confirms: client → symphony (TLS termination) → UDS → Harper
		ok(
			response.status >= 200 && response.status < 500,
			`Expected a valid HTTP response from Harper, got ${response.status}: ${response.body}`,
		);
	});

	test('multiple sequential requests are handled successfully', async () => {
		for (let i = 0; i < 5; i++) {
			const status = await new Promise<number>((resolve, reject) => {
				const req = request(
					{
						hostname: symphonyHost,
						port: requestPort,
						path: `/test-path-${i}`,
						method: 'GET',
						servername: sniHostname,
						ca: caCert,
						headers: { Host: sniHostname },
					},
					(res) => {
						res.resume(); // drain the response body
						res.on('end', () => resolve(res.statusCode!));
					},
				);
				req.on('error', reject);
				req.end();
			});

			ok(
				status >= 200 && status < 500,
				`Request ${i} should return a valid HTTP status, got ${status}`,
			);
		}
	});

	test('a failover route keeps serving after handshakes that closed connections it made to Harper', async (t) => {
		const { port, proxy: failoverProxy } = await startFailoverProxy(t);
		const aborted = 20;
		for (let i = 0; i < aborted; i++) {
			const socket = connectTcp({ host: symphonyHost, port });
			socket.on('error', () => {});
			socket.write(clientHello(sniHostname));
			await sleep(10);
			socket.destroy();
		}
		for (let i = 0; i < 200 && errorCount(failoverProxy, 'tls_handshake') < aborted; i++) await sleep(25);
		equal(errorCount(failoverProxy, 'tls_handshake'), aborted);

		const status = await httpStatus(
			connectTls({ host: symphonyHost, port, servername: sniHostname, ca: caCert })
		);
		ok(status >= 200 && status < 500, `got ${status}`);
		equal(errorCount(failoverProxy, 'upstream_connect'), 0);
	});

	test('a failover route replaces the connection Harper closes during a handshake past its 10 s limit', async (t) => {
		const { port, proxy: failoverProxy } = await startFailoverProxy(t, { tlsHandshakeTimeoutMs: 20_000 });
		const relay = await startSlowRelay(symphonyHost, port, 11_000);
		t.after(() => relay.close());

		const status = await httpStatus(
			connectTls({
				socket: connectTcp({ host: '127.0.0.1', port: relay.port }),
				servername: sniHostname,
				ca: caCert,
			})
		);
		ok(status >= 200 && status < 500, `got ${status}`);
		equal(errorCount(failoverProxy, 'upstream_connect'), 0);
	});
});
