/**
 * Metrics coverage: the in-process `metrics()` breakdown, the Prometheus renderer, and the
 * standalone server's admin endpoint over both a Unix socket and a loopback port.
 *
 * Requires the native addon to be built (npm run build:debug).
 */

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { spawn, ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import * as net from 'node:net';
import * as tls from 'node:tls';
import { SymphonyProxy } from '../ts/index.js';
// Not exported from the package root — the admin endpoint owns this shape (see ts/index.ts).
import { renderPrometheus, type MetricsSnapshot } from '../ts/admin.js';
import { generateSelfSignedCert, getFreePort, startEchoServer, tlsRoundTrip, sleep } from './util.js';

const SERVER_JS = path.join(__dirname, '..', 'ts', 'server.js');

async function waitFor(predicate: () => boolean | Promise<boolean>, timeoutMs = 5000, stepMs = 50): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (await predicate()) return;
		await sleep(stepMs);
	}
	throw new Error('waitFor: timed out');
}

/** GET over a Unix socket or a TCP port. */
function get(
	target: { socketPath: string } | { port: number },
	urlPath: string,
	method = 'GET'
): Promise<{ status: number; body: string; contentType: string }> {
	return new Promise((resolve, reject) => {
		const req = http.request({ ...target, path: urlPath, method }, (res) => {
			let body = '';
			res.setEncoding('utf8');
			res.on('data', (c) => (body += c));
			res.on('end', () =>
				resolve({ status: res.statusCode ?? 0, body, contentType: String(res.headers['content-type'] ?? '') })
			);
		});
		req.on('error', reject);
		req.end();
	});
}

function reasonCount(reasons: Array<{ reason: string; count: number }>, reason: string): number {
	const match = reasons.find((r) => r.reason === reason);
	assert.ok(match, `expected a '${reason}' entry; got ${reasons.map((r) => r.reason).join(', ')}`);
	return match.count;
}

describe('proxy.metrics()', () => {
	const cert = generateSelfSignedCert('localhost');
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;
	let tlsPort: number;
	let httpPort: number;

	before(async () => {
		echo = await startEchoServer();
		tlsPort = await getFreePort();
		httpPort = await getFreePort();
		proxy = new SymphonyProxy({
			listeners: [
				{ host: '127.0.0.1', port: tlsPort },
				{ host: '127.0.0.1', port: httpPort, mode: 'http' },
			],
			routes: [
				{
					sni: 'localhost',
					metricsGroup: 'tenant-1',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
		await proxy.start();
	});

	after(async () => {
		await proxy.stop().catch(() => {});
		await echo.close().catch(() => {});
	});

	it('reports one entry per configured listener, in order, with its mode', () => {
		const m = proxy.metrics();
		assert.equal(m.listeners.length, 2);
		assert.deepEqual(
			m.listeners.map((l) => [l.address, l.mode]),
			[
				[`127.0.0.1:${tlsPort}`, 'tls'],
				[`127.0.0.1:${httpPort}`, 'http'],
			]
		);
	});

	it('reports the live route count', () => {
		assert.equal(proxy.metrics().routes, 1);
		assert.equal(proxy.metrics().failingRoutes, 0);
	});

	it('reports configured route identity and optional group without client-derived labels', () => {
		assert.deepEqual(proxy.metrics().routeMetrics, [
			{
				route: 'localhost',
				metricsGroup: 'tenant-1',
				activeConnections: 0,
				connections: 0,
				errors: 0,
				bytesReceived: 0,
				bytesSent: 0,
				errorsByReason: [],
			},
		]);
	});

	it('emits every block and error reason, including the ones still at zero', () => {
		const listener = proxy.metrics().listeners[0];
		// A reason that only ever fires under protection config must still have a series.
		assert.equal(reasonCount(listener.blockedByReason, 'rate_limited'), 0);
		assert.equal(reasonCount(listener.errorsByReason, 'upstream_connect'), 0);
		assert.ok(listener.blockedByReason.some((r) => r.reason === 'max_connections'));
	});

	it('counts bytes in both directions across a proxied session', async () => {
		const before = proxy.metrics().listeners[0];
		const payload = Buffer.from('x'.repeat(4096));
		const echoed = await tlsRoundTrip({ port: tlsPort, servername: 'localhost', caCert: cert.cert, data: payload });
		assert.equal(echoed.length, payload.length);

		const after = proxy.metrics().listeners[0];
		assert.equal(after.accepted, before.accepted + 1);
		// The counter wraps the client *after* the handshake, so on a terminated-TLS route it
		// sees exactly the plaintext payload each way — no handshake and no record framing.
		assert.equal(after.bytesReceived, before.bytesReceived + payload.length);
		assert.equal(after.bytesSent, before.bytesSent + payload.length);
		const route = proxy.metrics().routeMetrics[0];
		assert.equal(route.connections, 1);
		assert.equal(route.bytesReceived, payload.length);
		assert.equal(route.bytesSent, payload.length);
	});

	it('preserves route counters across a hot reload with the same route identity', () => {
		const before = proxy.metrics().routeMetrics[0];
		proxy.updateConfig({
			routes: [
				{
					sni: 'localhost',
					metricsGroup: 'tenant-1',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
		assert.deepEqual(proxy.metrics().routeMetrics[0], before);
	});

	it('starts a fresh public series when the metrics group changes', () => {
		proxy.updateConfig({
			routes: [
				{
					sni: 'localhost',
					metricsGroup: 'tenant-2',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
		assert.deepEqual(proxy.metrics().routeMetrics, [
			{
				route: 'localhost',
				metricsGroup: 'tenant-2',
				activeConnections: 0,
				connections: 0,
				errors: 0,
				bytesReceived: 0,
				bytesSent: 0,
				errorsByReason: [],
			},
		]);

		proxy.updateConfig({
			routes: [
				{
					sni: 'localhost',
					metricsGroup: 'tenant-1',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
	});

	it('classifies an unroutable SNI as no_route rather than a generic error', async () => {
		const before = proxy.metrics().listeners[0];
		// No route for this SNI and no default route → symphony drops the connection.
		await tlsRoundTrip({ port: tlsPort, servername: 'nope.example.com', caCert: cert.cert, data: 'ping' }).catch(
			() => undefined
		);

		await waitFor(() => proxy.metrics().listeners[0].errors > before.errors);
		const after = proxy.metrics().listeners[0];
		assert.equal(reasonCount(after.errorsByReason, 'no_route'), reasonCount(before.errorsByReason, 'no_route') + 1);
		// The per-reason series always sum to the unlabeled total.
		assert.equal(
			after.errorsByReason.reduce((sum, r) => sum + r.count, 0),
			after.errors
		);
	});

	it('does not let an old connection decrement a re-added route identity', async () => {
		const socket = tls.connect({
			port: tlsPort,
			host: '127.0.0.1',
			servername: 'localhost',
			rejectUnauthorized: false,
		});
		await new Promise<void>((resolve, reject) => {
			socket.once('secureConnect', resolve);
			socket.once('error', reject);
		});
		await waitFor(() => proxy.metrics().routeMetrics[0]?.activeConnections === 1);

		proxy.updateConfig({ routes: [] });
		assert.deepEqual(proxy.metrics().routeMetrics, []);
		socket.destroy();

		proxy.updateConfig({
			routes: [
				{
					sni: 'localhost',
					metricsGroup: 'tenant-1',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
		await sleep(25);
		assert.equal(proxy.metrics().routeMetrics[0].activeConnections, 0);
		assert.equal(proxy.metrics().routeMetrics[0].connections, 0);
	});
});

describe('route metric identity validation', () => {
	function config(metricsGroup: string) {
		return {
			listeners: [{ host: '127.0.0.1', port: 0 }],
			routes: [
				{
					sni: 'tenant.test',
					metricsGroup,
					upstreams: [{ kind: 'tcp' as const, host: '127.0.0.1', port: 1 }],
					terminateTls: false,
				},
			],
		};
	}

	it('rejects oversized or control-character groups before proxy construction', () => {
		assert.throws(() => new SymphonyProxy(config('x'.repeat(129))), /metricsGroup exceeds 128 UTF-8 bytes/);
		assert.throws(() => new SymphonyProxy(config('tenant\rbreak')), /metricsGroup must not contain control characters/);
	});

	it('bounds configured route labels and isolates duplicate route keys', () => {
		const oversized = config('tenant');
		oversized.routes[0].sni = 'x'.repeat(256);
		assert.throws(() => new SymphonyProxy(oversized), /route SNI exceeds 255 UTF-8 bytes/);

		const controlled = config('tenant');
		controlled.routes[0].sni = 'tenant\ttest';
		assert.throws(() => new SymphonyProxy(controlled), /route SNI must not contain control characters/);

		const duplicate = config('tenant');
		duplicate.routes[0].sni = '*.tenant.test';
		const sibling = { ...duplicate.routes[0], sni: 'healthy.test' };
		const proxy = new SymphonyProxy({
			...duplicate,
			routes: [duplicate.routes[0], { ...duplicate.routes[0] }, sibling],
		});
		assert.deepEqual(
			proxy.metrics().routeMetrics.map((route) => route.route),
			['*.tenant.test', 'healthy.test']
		);
		assert.equal(proxy.metrics().failingRoutes, 1);
	});
});

// The three session outcomes are told apart by where the failure is raised, not by inspecting an
// io::ErrorKind — these lock that in, since a misclassification is invisible until an incident.
describe('proxy.metrics() error classification', () => {
	const cert = generateSelfSignedCert('localhost');
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;
	let tlsPort: number;
	let deadSocketPath: string;

	before(async () => {
		echo = await startEchoServer();
		tlsPort = await getFreePort();
		deadSocketPath = path.join(
			os.tmpdir(),
			`symphony-missing-${process.pid}-${Math.random().toString(36).slice(2)}.sock`
		);
		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: tlsPort, idleTimeoutMs: 300 }],
			routes: [
				{
					sni: 'idle.test',
					metricsGroup: 'tenant-idle',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
				{
					sni: 'dead.test',
					metricsGroup: 'tenant-dead',
					upstreams: [{ kind: 'uds', path: deadSocketPath }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
		});
		await proxy.start();
	});

	after(async () => {
		await proxy.stop().catch(() => {});
		await echo.close().catch(() => {});
	});

	it('records an unreachable upstream as upstream_connect', async () => {
		const before = reasonCount(proxy.metrics().listeners[0].errorsByReason, 'upstream_connect');
		assert.deepEqual(proxy.metrics().routeMetrics.find((r) => r.route === 'dead.test')?.errorsByReason, []);
		await tlsRoundTrip({ port: tlsPort, servername: 'dead.test', caCert: cert.cert, data: 'ping' }).catch(
			() => undefined
		);
		await waitFor(() => reasonCount(proxy.metrics().listeners[0].errorsByReason, 'upstream_connect') > before);
		assert.deepEqual(proxy.metrics().routeMetrics.find((r) => r.route === 'dead.test')?.errorsByReason, [
			{ reason: 'upstream_connect', count: 1 },
		]);
	});

	it('records a session that goes quiet as idle_timeout, not a stream error', async () => {
		const beforeIdle = reasonCount(proxy.metrics().listeners[0].errorsByReason, 'idle_timeout');
		const beforeStream = reasonCount(proxy.metrics().listeners[0].errorsByReason, 'stream');

		// Connect, complete the handshake, then send nothing until the 300ms idle timeout fires.
		const socket = tls.connect({
			port: tlsPort,
			host: '127.0.0.1',
			servername: 'idle.test',
			ca: cert.cert,
			rejectUnauthorized: false,
		});
		try {
			await new Promise<void>((resolve, reject) => {
				socket.once('secureConnect', resolve);
				socket.once('error', reject);
			});
			socket.on('error', () => {}); // the proxy dropping us is the expected outcome
			await waitFor(() => reasonCount(proxy.metrics().listeners[0].errorsByReason, 'idle_timeout') > beforeIdle, 5000);
		} finally {
			socket.destroy();
		}

		assert.equal(
			reasonCount(proxy.metrics().listeners[0].errorsByReason, 'stream'),
			beforeStream,
			'an idle timeout must not also be counted as a stream error'
		);
		assert.deepEqual(proxy.metrics().routeMetrics.find((r) => r.route === 'idle.test')?.errorsByReason, [
			{ reason: 'idle_timeout', count: 1 },
		]);
	});
});

describe('renderPrometheus', () => {
	const snapshot: MetricsSnapshot = {
		pid: 42,
		version: '9.9.9',
		startedAt: '2026-01-01T00:00:00.000Z',
		reloadedAt: '2026-01-01T00:01:00.000Z',
		proxies: [
			{
				ports: '80,443',
				metrics: {
					activeConnections: 3,
					blockedConnections: 2,
					pendingSuspended: 1,
					suspendedResolved: 5,
					suspendedUnresolved: 4,
					routes: 7,
					failingRoutes: 1,
					listeners: [
						{
							address: '0.0.0.0:443',
							mode: 'tls',
							activeConnections: 3,
							accepted: 10,
							blocked: 2,
							errors: 1,
							bytesReceived: 1024,
							bytesSent: 2048,
							blockedByReason: [
								{ reason: 'rate_limited', count: 2 },
								{ reason: 'no_sni', count: 0 },
							],
							errorsByReason: [{ reason: 'upstream_connect', count: 1 }],
						},
					],
					routeMetrics: [
						{
							route: 'api.example.com',
							metricsGroup: 'tenant-1',
							activeConnections: 2,
							connections: 8,
							errors: 1,
							bytesReceived: 768,
							bytesSent: 1536,
							errorsByReason: [{ reason: 'upstream_connect', count: 1 }],
						},
					],
				},
			},
		],
	};

	const output = renderPrometheus(snapshot);
	const lines = output.split('\n');

	it('declares HELP and TYPE exactly once per metric name', () => {
		const typeLines = lines.filter((l) => l.startsWith('# TYPE '));
		const names = typeLines.map((l) => l.split(' ')[2]);
		assert.deepEqual([...new Set(names)].length, names.length, `duplicate TYPE declarations in:\n${output}`);
		// Both `outcome` samples share one declaration.
		assert.equal(typeLines.filter((l) => l.includes('symphony_suspended_total')).length, 1);
	});

	// Samples of one metric name must be contiguous under a single HELP/TYPE pair. Emitting in
	// proxy → listener call order would interleave them once a second proxy exists, and strict
	// parsers reject or drop the split group.
	it('keeps every metric name contiguous across multiple proxies', () => {
		const second = structuredClone(snapshot.proxies[0]);
		second.ports = '8443';
		second.metrics.listeners[0].address = '0.0.0.0:8443';
		const multi = renderPrometheus({ ...snapshot, proxies: [snapshot.proxies[0], second] }).split('\n');

		const seen = new Set<string>();
		let previous = '';
		for (const line of multi) {
			if (!line || line.startsWith('#')) continue;
			const name = line.slice(0, Math.min(...[line.indexOf('{'), line.indexOf(' ')].filter((i) => i >= 0)));
			if (name !== previous) {
				assert.ok(!seen.has(name), `samples for ${name} are split across the output`);
				seen.add(name);
				previous = name;
			}
		}
		// Both proxies really are present, so the check above wasn't vacuous.
		assert.ok(multi.includes('symphony_routes{proxy="80,443"} 7'));
		assert.ok(multi.includes('symphony_routes{proxy="8443"} 7'));
	});

	it('labels every proxy-scoped and listener-scoped sample', () => {
		assert.ok(lines.includes('symphony_routes{proxy="80,443"} 7'));
		assert.ok(lines.includes('symphony_routes_failing{proxy="80,443"} 1'));
		assert.ok(lines.includes('symphony_suspended_total{proxy="80,443",outcome="resolved"} 5'));
		assert.ok(lines.includes('symphony_suspended_total{proxy="80,443",outcome="unresolved"} 4'));
		assert.ok(lines.includes('symphony_listener_accepted_total{proxy="80,443",listener="0.0.0.0:443",mode="tls"} 10'));
		assert.ok(
			lines.includes('symphony_listener_bytes_received_total{proxy="80,443",listener="0.0.0.0:443",mode="tls"} 1024')
		);
		assert.ok(
			lines.includes(
				'symphony_route_connections_total{proxy="80,443",route="api.example.com",group="tenant-1"} 8'
			)
		);
		assert.ok(
			lines.includes(
				'symphony_route_errors_total{proxy="80,443",route="api.example.com",group="tenant-1",reason="upstream_connect"} 1'
			)
		);
	});

	it('emits blocked/error counts only under their reason label', () => {
		assert.ok(
			lines.includes(
				'symphony_listener_blocked_total{proxy="80,443",listener="0.0.0.0:443",mode="tls",reason="rate_limited"} 2'
			)
		);
		// A zero-valued reason still gets a series, so it exists before the first incident.
		assert.ok(
			lines.includes(
				'symphony_listener_blocked_total{proxy="80,443",listener="0.0.0.0:443",mode="tls",reason="no_sni"} 0'
			)
		);
		// No unlabeled duplicate of the same number.
		assert.ok(!lines.some((l) => /^symphony_listener_blocked_total\{[^}]*\}\s/.test(l) && !l.includes('reason=')));
	});

	// Route/group deliberately make the optional admin endpoint tenant-identifying. Host Manager's
	// default Docker bridge does not expose host loopback to tenant containers, but host-local
	// processes and downstream collectors can see these labels, so any further identity dimension
	// remains a deliberate API/security decision.
	it('restricts tenant identity to the deliberate route and group labels', () => {
		const allowed = new Set(['version', 'proxy', 'listener', 'mode', 'reason', 'outcome', 'route', 'group']);
		for (const line of lines) {
			const labelSet = line.match(/\{(.*)\}/)?.[1];
			if (!labelSet) continue;
			// Keys sit at the start or after a comma; a label *value* may itself contain a comma
			// (proxy="80,443"), so the boundary has to be matched rather than split on.
			for (const [, , key] of labelSet.matchAll(/(^|,)([a-z_]+)="/g)) {
				assert.ok(allowed.has(key), `unexpected metric label '${key}' — is it tenant-identifying?`);
			}
			if (line.startsWith('symphony_listener_')) {
				assert.ok(!/(^|,)route=|(^|,)group=/.test(labelSet), 'existing listener series must not gain route labels');
			}
		}
	});

	it('carries the version in build_info and timestamps in seconds', () => {
		assert.ok(lines.includes('symphony_build_info{version="9.9.9"} 1'));
		assert.ok(lines.includes(`symphony_start_time_seconds ${Date.parse(snapshot.startedAt) / 1000}`));
		assert.ok(lines.includes(`symphony_config_reload_time_seconds ${Date.parse(snapshot.reloadedAt) / 1000}`));
	});

	it('escapes label values', () => {
		const escaped = renderPrometheus({
			...snapshot,
			version: 'a"b\\c',
			proxies: [
				{
					...snapshot.proxies[0],
					metrics: {
						...snapshot.proxies[0].metrics,
						routeMetrics: [
							{
								...snapshot.proxies[0].metrics.routeMetrics[0],
								route: 'a"b\\c\nroute',
								metricsGroup: 'tenant\rgroup',
							},
						],
					},
				},
			],
		});
		assert.ok(escaped.includes('symphony_build_info{version="a\\"b\\\\c"} 1'));
		assert.ok(escaped.includes('route="a\\"b\\\\c\\nroute",group="tenant\\ngroup"'));
	});

	it('keeps large-route output to four base samples per route plus non-zero errors', () => {
		const count = 2000;
		const routeMetrics = Array.from({ length: count }, (_, i) => ({
			route: `tenant-${i}.example.com`,
			metricsGroup: `tenant-${i}`,
			activeConnections: 0,
			connections: 0,
			errors: 0,
			bytesReceived: 0,
			bytesSent: 0,
			errorsByReason: [],
		}));
		const rendered = renderPrometheus({
			...snapshot,
			proxies: [
				{
					...snapshot.proxies[0],
					metrics: { ...snapshot.proxies[0].metrics, routeMetrics },
				},
			],
		});
		assert.equal(rendered.match(/^symphony_route_connections_total\{/gm)?.length, count);
		assert.equal(rendered.match(/^symphony_route_errors_total\{/gm)?.length ?? 0, 0);
	});
});

describe('symphony-server admin endpoint', () => {
	const cert = generateSelfSignedCert('localhost');
	let dir: string;
	let configPath: string;
	let statusPath: string;
	let socketPath: string;
	let adminPort: number;
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let child: ChildProcess;
	let stderr = '';
	let shuttingDown = false;

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-metrics-test-'));
		configPath = path.join(dir, 'config.json');
		statusPath = path.join(dir, 'status.json');
		socketPath = path.join(dir, 'admin.sock');
		echo = await startEchoServer();
		proxyPort = await getFreePort();
		adminPort = await getFreePort();

		fs.writeFileSync(
			configPath,
			JSON.stringify({
				version: 1,
				admin: { socketPath, port: adminPort, host: '127.0.0.1' },
				proxies: [
					{
						listeners: [{ host: '127.0.0.1', port: proxyPort }],
						routes: [
							{
								sni: 'localhost',
								metricsGroup: 'tenant-exact',
								upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
								terminateTls: true,
								cert: { certChain: cert.cert, privateKey: cert.key },
							},
							{
								sni: '*.localhost',
								metricsGroup: 'tenant-wildcard',
								upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
								terminateTls: true,
								cert: { certChain: cert.cert, privateKey: cert.key },
							},
						],
					},
				],
			})
		);

		child = spawn(process.execPath, [SERVER_JS, '--config', configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
		child.stderr?.on('data', (d) => (stderr += d.toString()));
		child.on('exit', (code, sig) => {
			if (!shuttingDown) stderr += `\n[child exited early code=${code} sig=${sig}]`;
		});
		await waitFor(() => fs.existsSync(statusPath) && fs.existsSync(socketPath), 8000);
	});

	after(async () => {
		shuttingDown = true;
		if (child && child.exitCode === null && child.signalCode === null) {
			child.kill('SIGTERM');
			await waitFor(() => child.exitCode !== null || child.signalCode !== null, 3000).catch(() =>
				child.kill('SIGKILL')
			);
		}
		await echo.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('serves Prometheus text over the unix socket', async () => {
		const res = await get({ socketPath }, '/metrics');
		assert.equal(res.status, 200, stderr);
		assert.match(res.contentType, /text\/plain; version=0\.0\.4/);
		assert.match(res.body, /^# HELP symphony_build_info /m);
		assert.match(
			res.body,
			new RegExp(
				`symphony_listener_accepted_total\\{proxy="${proxyPort}",listener="127\\.0\\.0\\.1:${proxyPort}",mode="tls"\\} \\d+`
			)
		);
		assert.match(
			res.body,
			new RegExp(
				`symphony_route_connections_total\\{proxy="${proxyPort}",route="\\*\\.localhost",group="tenant-wildcard"\\} 0`
			)
		);
	});

	it('serves the same snapshot as JSON over the loopback port', async () => {
		const res = await get({ port: adminPort }, '/metrics.json');
		assert.equal(res.status, 200, stderr);
		assert.match(res.contentType, /application\/json/);
		const snapshot = JSON.parse(res.body) as MetricsSnapshot;
		assert.equal(snapshot.proxies.length, 1);
		assert.equal(snapshot.proxies[0].ports, String(proxyPort));
		assert.equal(snapshot.proxies[0].metrics.listeners[0].address, `127.0.0.1:${proxyPort}`);
	});

	it('reflects live traffic on the next scrape', async () => {
		const before = JSON.parse((await get({ socketPath }, '/metrics.json')).body) as MetricsSnapshot;
		await tlsRoundTrip({ port: proxyPort, servername: 'localhost', caCert: cert.cert, data: 'hello' });
		await tlsRoundTrip({ port: proxyPort, servername: 'random.localhost', caCert: cert.cert, data: 'wild' });
		const after = JSON.parse((await get({ socketPath }, '/metrics.json')).body) as MetricsSnapshot;

		assert.equal(after.proxies[0].metrics.listeners[0].accepted, before.proxies[0].metrics.listeners[0].accepted + 2);
		assert.ok(after.proxies[0].metrics.listeners[0].bytesSent > before.proxies[0].metrics.listeners[0].bytesSent);
		const exact = after.proxies[0].metrics.routeMetrics.find((route) => route.route === 'localhost');
		const wildcard = after.proxies[0].metrics.routeMetrics.find((route) => route.route === '*.localhost');
		assert.equal(exact?.metricsGroup, 'tenant-exact');
		assert.equal(exact?.connections, 1);
		assert.equal(wildcard?.metricsGroup, 'tenant-wildcard');
		assert.equal(wildcard?.connections, 1);
		const prometheus = (await get({ socketPath }, '/metrics')).body;
		assert.match(prometheus, /route="\*\.localhost",group="tenant-wildcard"/);
		assert.ok(!prometheus.includes('random.localhost'), 'wildcard metrics must never use the client-provided hostname');
	});

	it('restricts the unix socket to owner and group', () => {
		assert.equal(fs.statSync(socketPath).mode & 0o777, 0o660);
	});

	it('answers /health with the pid and served ports', async () => {
		const res = await get({ port: adminPort }, '/health');
		assert.equal(res.status, 200);
		const health = JSON.parse(res.body) as { ok: boolean; pid: number; ports: number[] };
		assert.equal(health.ok, true);
		assert.equal(health.pid, child.pid);
		assert.deepEqual(health.ports, [proxyPort]);
	});

	it('404s an unknown path and 405s a non-GET', async () => {
		assert.equal((await get({ port: adminPort }, '/nope')).status, 404);
		assert.equal((await get({ port: adminPort }, '/metrics', 'POST')).status, 405);
	});

	it('ignores a query string on /metrics', async () => {
		const res = await get({ port: adminPort }, '/metrics?foo=bar');
		assert.equal(res.status, 200);
	});

	// Shutdown deliberately does NOT unlink the published path — any check-then-unlink can delete
	// a successor's live socket in the window between the two syscalls. What has to hold is that
	// the endpoint stops answering; reclaiming the pathname is the next binder's job, atomically.
	it('stops serving on shutdown and leaves the path safely reclaimable', async () => {
		shuttingDown = true;
		child.kill('SIGTERM');
		await waitFor(() => child.exitCode !== null || child.signalCode !== null, 5000);

		await assert.rejects(
			() => get({ socketPath }, '/health'),
			(err: NodeJS.ErrnoException) => err.code === 'ECONNREFUSED',
			'a dead endpoint must refuse connections, not hang or answer'
		);
	});
});

// A SIGKILLed process never runs its shutdown path, so the socket file survives it. The next
// process must reclaim it — but only after proving nobody is listening, since unlinking a live
// socket would silently steal the endpoint from a running symphony.
describe('symphony-server admin endpoint (stale socket recovery)', () => {
	const cert = generateSelfSignedCert('localhost');
	let dir: string;
	let socketPath: string;
	let survivor: ChildProcess | null = null;

	function writeConfig(configPath: string, proxyPort: number, echoPort: number): void {
		fs.writeFileSync(
			configPath,
			JSON.stringify({
				version: 1,
				admin: { socketPath },
				proxies: [
					{
						listeners: [{ host: '127.0.0.1', port: proxyPort }],
						routes: [
							{
								sni: 'localhost',
								upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echoPort }],
								terminateTls: true,
								cert: { certChain: cert.cert, privateKey: cert.key },
							},
						],
					},
				],
			})
		);
	}

	before(() => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-stale-sock-'));
		socketPath = path.join(dir, 'admin.sock');
	});

	after(async () => {
		if (survivor && survivor.exitCode === null && survivor.signalCode === null) {
			survivor.kill('SIGKILL');
			await waitFor(() => survivor!.exitCode !== null || survivor!.signalCode !== null, 3000).catch(() => {});
		}
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('reclaims a socket left behind by a SIGKILLed process', async () => {
		const echo = await startEchoServer();
		try {
			const firstConfig = path.join(dir, 'first.json');
			const firstStatus = path.join(dir, 'first-status.json');
			writeConfig(firstConfig, await getFreePort(), echo.port);
			const first = spawn(process.execPath, [SERVER_JS, '--config', firstConfig, '--status', firstStatus], {
				stdio: ['ignore', 'pipe', 'pipe'],
			});
			await waitFor(() => fs.existsSync(socketPath), 8000);

			first.kill('SIGKILL');
			await waitFor(() => first.exitCode !== null || first.signalCode !== null, 5000);
			assert.ok(fs.existsSync(socketPath), 'SIGKILL should leave the socket file behind');

			// Second process: same socket path, now stale.
			const secondConfig = path.join(dir, 'second.json');
			const secondStatus = path.join(dir, 'second-status.json');
			writeConfig(secondConfig, await getFreePort(), echo.port);
			let stderr = '';
			survivor = spawn(process.execPath, [SERVER_JS, '--config', secondConfig, '--status', secondStatus], {
				stdio: ['ignore', 'pipe', 'pipe'],
			});
			survivor.stderr?.on('data', (d) => (stderr += d.toString()));
			await waitFor(() => fs.existsSync(secondStatus), 8000);

			// The bind is retried on a timer if it loses the race, so allow a couple of cycles.
			await waitFor(async () => {
				const res = await get({ socketPath }, '/health').catch(() => null);
				return res?.status === 200;
			}, 15000);
			const health = JSON.parse((await get({ socketPath }, '/health')).body) as { pid: number };
			assert.equal(health.pid, survivor.pid, `the new process must own the socket; stderr:\n${stderr}`);
		} finally {
			await echo.close().catch(() => {});
		}
	});

	// The inverse, and the one that actually costs something to get wrong: a socket that is still
	// being served must survive a would-be reclaimer, whatever the probe happens to return. A
	// permission-denied probe is not evidence that nobody is listening.
	it('leaves a live socket alone even when the probe cannot connect to it', async () => {
		const echo = await startEchoServer();
		const livePath = path.join(dir, 'live.sock');
		// Stand in for a running symphony: a real listening socket the reclaimer must not delete.
		const incumbent = net.createServer();
		await new Promise<void>((resolve) => incumbent.listen(livePath, resolve));
		const liveIno = fs.statSync(livePath).ino;

		try {
			// 0o000 makes connect() fail with EACCES rather than ECONNREFUSED. Treating any probe
			// error as "stale" would unlink this live socket.
			fs.chmodSync(livePath, 0o000);

			const configPath = path.join(dir, 'contend.json');
			const statusPath = path.join(dir, 'contend-status.json');
			fs.writeFileSync(
				configPath,
				JSON.stringify({
					version: 1,
					admin: { socketPath: livePath },
					proxies: [
						{
							listeners: [{ host: '127.0.0.1', port: await getFreePort() }],
							routes: [
								{
									sni: 'localhost',
									upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
									terminateTls: true,
									cert: { certChain: cert.cert, privateKey: cert.key },
								},
							],
						},
					],
				})
			);

			const contender = spawn(process.execPath, [SERVER_JS, '--config', configPath, '--status', statusPath], {
				stdio: ['ignore', 'pipe', 'pipe'],
			});
			try {
				// It boots and proxies regardless — losing the admin bind must never block startup.
				await waitFor(() => fs.existsSync(statusPath), 8000);
				// Give the retry timer a cycle to (wrongly) reclaim, if it were going to.
				await sleep(1000);

				assert.ok(fs.existsSync(livePath), 'the live socket must not have been unlinked');
				assert.equal(fs.statSync(livePath).ino, liveIno, 'the live socket must not have been replaced');
			} finally {
				contender.kill('SIGKILL');
				await waitFor(() => contender.exitCode !== null || contender.signalCode !== null, 3000).catch(() => {});
			}
		} finally {
			fs.chmodSync(livePath, 0o660);
			await new Promise<void>((resolve) => incumbent.close(() => resolve()));
			await echo.close().catch(() => {});
		}
	});
});
