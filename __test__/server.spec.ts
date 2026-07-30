/**
 * Integration tests for the standalone symphony-server bin (dist/server.js).
 *
 * Spawns the server as a real child process, pointed at a JSON config file with a
 * cert referenced by `privateKeyFile`, and verifies: it boots and serves TLS, it
 * writes a status file with the version, and it hot-reloads when the config changes.
 *
 * Requires the native addon to be built (npm run build:debug).
 */

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { spawn, ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import * as tls from 'node:tls';
import { generateSelfSignedCert, getFreePort, startEchoServer, tlsRoundTrip, sleep } from './util.js';

// server.js sits next to this compiled spec's sibling ts/ dir: dist-test/ts/server.js
const SERVER_JS = path.join(__dirname, '..', 'ts', 'server.js');

// status.json reports the package version; read it from the same source of truth
// the server does rather than hardcoding, so a version bump doesn't break the test.
const PKG_VERSION = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'package.json'), 'utf8')).version;

function writeConfigAtomic(configPath: string, config: unknown): void {
	const tmp = `${configPath}.tmp`;
	fs.writeFileSync(tmp, JSON.stringify(config, null, 2));
	fs.renameSync(tmp, configPath);
}

async function waitFor(predicate: () => boolean | Promise<boolean>, timeoutMs = 5000, stepMs = 50): Promise<void> {
	const deadline = Date.now() + timeoutMs;
	while (Date.now() < deadline) {
		if (await predicate()) return;
		await sleep(stepMs);
	}
	throw new Error('waitFor: timed out');
}

interface RunningServer {
	child: ChildProcess;
	getStderr: () => string;
	/** stdout carries the server's own lifecycle log lines (log(), not logErr()). */
	getStdout: () => string;
	markShutdown: () => void;
}

function spawnServer(configPath: string, statusPath?: string): RunningServer {
	let stderr = '';
	let stdout = '';
	let shuttingDown = false;
	const args = [SERVER_JS, '--config', configPath];
	if (statusPath) args.push('--status', statusPath);
	const child = spawn(process.execPath, args, { stdio: ['ignore', 'pipe', 'pipe'] });
	child.stderr?.on('data', (d) => (stderr += d.toString()));
	child.stdout?.on('data', (d) => (stdout += d.toString()));
	child.on('exit', (code, sig) => {
		if (!shuttingDown) stderr += `\n[child exited early code=${code} sig=${sig}]`;
	});
	return { child, getStderr: () => stderr, getStdout: () => stdout, markShutdown: () => (shuttingDown = true) };
}

async function killServer(server: RunningServer): Promise<void> {
	server.markShutdown();
	if (server.child.exitCode === null) {
		server.child.kill('SIGTERM');
		await waitFor(() => server.child.exitCode !== null, 3000).catch(() => server.child.kill('SIGKILL'));
	}
}

// A round-trip that resolves true only when the server presents a cert that verifies
// against `caCert` for `servername` — used to detect which cert is live after a rotation.
async function servesCert(port: number, servername: string, caCert: string): Promise<boolean> {
	try {
		await tlsRoundTrip({ port, servername, caCert, data: Buffer.from('ping'), rejectUnauthorized: true });
		return true;
	} catch {
		return false;
	}
}

describe('symphony-server (standalone process)', () => {
	const cert = generateSelfSignedCert('localhost');
	let dir: string;
	let configPath: string;
	let statusPath: string;
	let keyFile: string;
	let proxyPort: number;
	let echoA: Awaited<ReturnType<typeof startEchoServer>>;
	let echoB: Awaited<ReturnType<typeof startEchoServer>>;
	let child: ChildProcess;
	let stderr = '';
	let shuttingDown = false;

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-server-test-'));
		configPath = path.join(dir, 'config.json');
		statusPath = path.join(dir, 'status.json');
		keyFile = path.join(dir, 'privkey.pem');
		fs.writeFileSync(keyFile, cert.key); // private key on disk, referenced by path

		echoA = await startEchoServer();
		echoB = await startEchoServer();
		proxyPort = await getFreePort();

		writeConfigAtomic(configPath, {
			version: 1,
			proxies: [
				{
					listeners: [{ host: '127.0.0.1', port: proxyPort }],
					routes: [
						{
							sni: 'localhost',
							upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echoA.port }],
							terminateTls: true,
							cert: { certChain: cert.cert, privateKeyFile: keyFile },
						},
					],
				},
			],
		});

		child = spawn(process.execPath, [SERVER_JS, '--config', configPath], {
			stdio: ['ignore', 'pipe', 'pipe'],
		});
		child.stderr?.on('data', (d) => (stderr += d.toString()));
		child.on('exit', (code, sig) => {
			if (!shuttingDown) stderr += `\n[child exited early code=${code} sig=${sig}]`;
		});

		// Boot is confirmed by the status file appearing.
		await waitFor(() => fs.existsSync(statusPath));
	});

	after(async () => {
		shuttingDown = true;
		if (child && child.exitCode === null) {
			child.kill('SIGTERM');
			await waitFor(() => child.exitCode !== null, 3000).catch(() => child.kill('SIGKILL'));
		}
		await echoA.close().catch(() => {});
		await echoB.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('writes a status file with pid and version', () => {
		const status = JSON.parse(fs.readFileSync(statusPath, 'utf8'));
		assert.equal(status.pid, child.pid);
		assert.equal(status.version, PKG_VERSION);
		assert.ok(status.ports.includes(proxyPort), `ports ${status.ports} should include ${proxyPort}`);
	});

	it('serves TLS with a key loaded from privateKeyFile', async () => {
		const payload = Buffer.from('hello-standalone');
		const res = await tlsRoundTrip({
			port: proxyPort,
			servername: 'localhost',
			caCert: cert.cert,
			data: payload,
			rejectUnauthorized: true,
		});
		assert.deepEqual(res, payload);
	});

	it('hot-reloads routes when the config file changes', async () => {
		// Close echoA and repoint the route at echoB. If the server reloaded, the
		// round-trip succeeds via echoB; if it ignored the change it would still try
		// the now-closed echoA and fail.
		await echoA.close();
		writeConfigAtomic(configPath, {
			version: 1,
			proxies: [
				{
					listeners: [{ host: '127.0.0.1', port: proxyPort }],
					routes: [
						{
							sni: 'localhost',
							upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echoB.port }],
							terminateTls: true,
							cert: { certChain: cert.cert, privateKeyFile: keyFile },
						},
					],
				},
			],
		});

		const payload = Buffer.from('after-reload');
		let res: Buffer | null = null;
		// Poll until the echoed bytes match: a connection to the now-closed echoA resolves
		// with an empty buffer, so only a full echo proves the route was repointed to echoB.
		await waitFor(
			async () => {
				try {
					const r = await tlsRoundTrip({
						port: proxyPort,
						servername: 'localhost',
						caCert: cert.cert,
						data: payload,
						rejectUnauthorized: true,
					});
					if (r.length === payload.length && Buffer.compare(r, payload) === 0) {
						res = r;
						return true;
					}
					return false;
				} catch {
					return false;
				}
			},
			8000,
			150
		);
		assert.deepEqual(res, payload, `server did not reload routes. stderr:\n${stderr}`);
	});
});

describe('symphony-server (cert-file hot reload)', () => {
	// Two independent certs for the same host: rotating from A to B on disk (without
	// touching config.json) must make the server serve B.
	const certA = generateSelfSignedCert('localhost');
	const certB = generateSelfSignedCert('localhost');
	let dir: string;
	let configPath: string;
	let statusPath: string;
	let certFile: string;
	let keyFile: string;
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let server: RunningServer;

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-certrot-'));
		configPath = path.join(dir, 'config.json');
		statusPath = path.join(dir, 'status.json');
		certFile = path.join(dir, 'fullchain.pem'); // both cert and key referenced by path
		keyFile = path.join(dir, 'privkey.pem');
		fs.writeFileSync(certFile, certA.cert);
		fs.writeFileSync(keyFile, certA.key);

		echo = await startEchoServer();
		proxyPort = await getFreePort();

		writeConfigAtomic(configPath, {
			version: 1,
			proxies: [
				{
					listeners: [{ host: '127.0.0.1', port: proxyPort }],
					routes: [
						{
							sni: 'localhost',
							upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
							terminateTls: true,
							cert: { certChainFile: certFile, privateKeyFile: keyFile },
						},
					],
				},
			],
		});

		server = spawnServer(configPath);
		await waitFor(() => fs.existsSync(statusPath));
	});

	after(async () => {
		await killServer(server);
		await echo.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('serves the initial cert loaded from certChainFile', async () => {
		await waitFor(() => servesCert(proxyPort, 'localhost', certA.cert));
	});

	it('hot-reloads a rotated cert file without a config.json change', async () => {
		// Overwrite the cert+key files in place (key first, then chain) — no config write. A
		// running symphony watches the referenced files, so it should pick up cert B. If a
		// reconcile happens mid-write, the transient key/cert mismatch is a logged per-route
		// skip that self-heals on the next event (Fix #2), so the rotation still converges.
		fs.writeFileSync(keyFile, certB.key);
		fs.writeFileSync(certFile, certB.cert);

		await waitFor(() => servesCert(proxyPort, 'localhost', certB.cert), 8000, 150);
		// And the old cert is no longer trusted-verifiable (fully rotated, not both live).
		assert.equal(
			await servesCert(proxyPort, 'localhost', certA.cert),
			false,
			`old cert still served after rotation. stderr:\n${server.getStderr()}`
		);
	});
});

describe('symphony-server (per-route cert isolation)', () => {
	// A healthy tenant and a broken one (mismatched cert/key → rustls KeyMismatch) share a
	// listener. The broken route must be dropped without taking the healthy co-tenant down.
	const good = generateSelfSignedCert('good.local');
	const certX = generateSelfSignedCert('bad.local');
	const certY = generateSelfSignedCert('bad.local');
	let dir: string;
	let configPath: string;
	let statusPath: string;
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let server: RunningServer;

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-isolation-'));
		configPath = path.join(dir, 'config.json');
		statusPath = path.join(dir, 'status.json');
		const goodCert = path.join(dir, 'good.crt');
		const goodKey = path.join(dir, 'good.key');
		const badCert = path.join(dir, 'bad.crt');
		const badKey = path.join(dir, 'bad.key');
		fs.writeFileSync(goodCert, good.cert);
		fs.writeFileSync(goodKey, good.key);
		fs.writeFileSync(badCert, certX.cert); // chain from X…
		fs.writeFileSync(badKey, certY.key); // …paired with an unrelated key → KeyMismatch

		echo = await startEchoServer();
		proxyPort = await getFreePort();

		writeConfigAtomic(configPath, {
			version: 1,
			proxies: [
				{
					listeners: [{ host: '127.0.0.1', port: proxyPort }],
					routes: [
						{
							sni: 'good.local',
							upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
							terminateTls: true,
							cert: { certChainFile: goodCert, privateKeyFile: goodKey },
						},
						{
							sni: 'bad.local',
							upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
							terminateTls: true,
							cert: { certChainFile: badCert, privateKeyFile: badKey },
						},
					],
				},
			],
		});

		server = spawnServer(configPath);
		await waitFor(() => fs.existsSync(statusPath));
	});

	after(async () => {
		await killServer(server);
		await echo.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('serves the healthy co-tenant despite a broken route on the same port', async () => {
		const payload = Buffer.from('healthy-tenant');
		const res = await tlsRoundTrip({
			port: proxyPort,
			servername: 'good.local',
			caCert: good.cert,
			data: payload,
			rejectUnauthorized: true,
		});
		assert.deepEqual(res, payload);
	});

	it('drops only the broken route and logs the skip', async () => {
		// The bad SNI has no route (KeyMismatch skipped it), so the handshake never completes.
		await assert.rejects(
			tlsRoundTrip({
				port: proxyPort,
				servername: 'bad.local',
				caCert: certX.cert,
				data: Buffer.from('x'),
				rejectUnauthorized: true,
			})
		);
		assert.match(server.getStderr(), /skipping route 'bad\.local'/);
	});
});

describe('symphony-server (listener default-cert hot reload)', () => {
	// A route that relies on the listener-level defaultCert (no per-route cert). The
	// listener default is frozen at construction, so a rotation must force a proxy recreate
	// (not a route-only hot-swap) — the resolved-listener signature makes that happen.
	const certA = generateSelfSignedCert('localhost');
	const certB = generateSelfSignedCert('localhost');
	let dir: string;
	let configPath: string;
	let statusPath: string;
	let certFile: string;
	let keyFile: string;
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let server: RunningServer;

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-listenercert-'));
		configPath = path.join(dir, 'config.json');
		statusPath = path.join(dir, 'status.json');
		certFile = path.join(dir, 'fullchain.pem');
		keyFile = path.join(dir, 'privkey.pem');
		fs.writeFileSync(certFile, certA.cert);
		fs.writeFileSync(keyFile, certA.key);

		echo = await startEchoServer();
		proxyPort = await getFreePort();

		writeConfigAtomic(configPath, {
			version: 1,
			proxies: [
				{
					listeners: [
						{ host: '127.0.0.1', port: proxyPort, defaultCert: { certChainFile: certFile, privateKeyFile: keyFile } },
					],
					routes: [
						{
							sni: 'localhost',
							upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
							terminateTls: true, // no per-route cert → uses the listener defaultCert
						},
					],
				},
			],
		});

		server = spawnServer(configPath);
		await waitFor(() => fs.existsSync(statusPath));
	});

	after(async () => {
		await killServer(server);
		await echo.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('hot-reloads a rotated listener defaultCert file without a config.json change', async () => {
		await waitFor(() => servesCert(proxyPort, 'localhost', certA.cert));
		fs.writeFileSync(keyFile, certB.key);
		fs.writeFileSync(certFile, certB.cert);
		await waitFor(() => servesCert(proxyPort, 'localhost', certB.cert), 8000, 150);
		assert.equal(
			await servesCert(proxyPort, 'localhost', certA.cert),
			false,
			`old listener cert still served after rotation. stderr:\n${server.getStderr()}`
		);
	});
});

describe('symphony-server (route cert-file read failure is isolated)', () => {
	// Two by-file routes on one port. If one route's cert file goes missing (ENOENT mid-
	// rotation), it must not block the OTHER route's rotation on the same port-set — the
	// unreadable route keeps its last-good cert while the healthy route's rotation applies.
	const a1 = generateSelfSignedCert('a.local');
	const a2 = generateSelfSignedCert('a.local');
	const b = generateSelfSignedCert('b.local');
	let dir: string;
	let configPath: string;
	let statusPath: string;
	let aCertFile: string;
	let aKeyFile: string;
	let bCertFile: string;
	let bKeyFile: string;
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let server: RunningServer;

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-routefail-'));
		configPath = path.join(dir, 'config.json');
		statusPath = path.join(dir, 'status.json');
		aCertFile = path.join(dir, 'a.crt');
		aKeyFile = path.join(dir, 'a.key');
		bCertFile = path.join(dir, 'b.crt');
		bKeyFile = path.join(dir, 'b.key');
		fs.writeFileSync(aCertFile, a1.cert);
		fs.writeFileSync(aKeyFile, a1.key);
		fs.writeFileSync(bCertFile, b.cert);
		fs.writeFileSync(bKeyFile, b.key);

		echo = await startEchoServer();
		proxyPort = await getFreePort();

		writeConfigAtomic(configPath, {
			version: 1,
			proxies: [
				{
					listeners: [{ host: '127.0.0.1', port: proxyPort }],
					routes: [
						{
							sni: 'a.local',
							upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
							terminateTls: true,
							cert: { certChainFile: aCertFile, privateKeyFile: aKeyFile },
						},
						{
							sni: 'b.local',
							upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
							terminateTls: true,
							cert: { certChainFile: bCertFile, privateKeyFile: bKeyFile },
						},
					],
				},
			],
		});

		server = spawnServer(configPath);
		await waitFor(() => fs.existsSync(statusPath));
	});

	after(async () => {
		await killServer(server);
		await echo.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('rotates the healthy route while a co-tenant cert file is missing, retaining its last-good', async () => {
		await waitFor(() => servesCert(proxyPort, 'a.local', a1.cert));
		await waitFor(() => servesCert(proxyPort, 'b.local', b.cert));

		// b.local's cert file disappears (mid-rotation ENOENT); a.local rotates at the same time.
		fs.rmSync(bCertFile);
		fs.writeFileSync(aKeyFile, a2.key);
		fs.writeFileSync(aCertFile, a2.cert);

		// a.local's rotation must apply despite b.local's unreadable file…
		await waitFor(() => servesCert(proxyPort, 'a.local', a2.cert), 8000, 150);
		// …and b.local keeps serving its last-good cert (route isolated + carried forward).
		assert.equal(
			await servesCert(proxyPort, 'b.local', b.cert),
			true,
			`co-tenant b.local was dropped when its cert file went missing. stderr:\n${server.getStderr()}`
		);
		assert.match(server.getStderr(), /route 'b\.local'/);
	});
});

describe('symphony-server (protection hot-swap via config file)', () => {
	// Verifies that adding a protection block to a previously-unprotected listener forces
	// a seamless recreate (fix 1: hasProtection in listenerSig), and that removing it
	// recreates again without protection. Tests both transitions end-to-end.
	const cert = generateSelfSignedCert('localhost');
	let dir: string;
	let configPath: string;
	let statusPath: string;
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let server: RunningServer;

	const baseRoute = () => ({
		sni: 'localhost',
		upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
		terminateTls: true,
		cert: { certChain: cert.cert, privateKey: cert.key },
	});

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-prot-hot-'));
		configPath = path.join(dir, 'config.json');
		statusPath = path.join(dir, 'status.json');

		echo = await startEchoServer();
		proxyPort = await getFreePort();

		// Start WITHOUT protection — 127.0.0.1 is allowed.
		writeConfigAtomic(configPath, {
			version: 1,
			proxies: [{
				listeners: [{ host: '127.0.0.1', port: proxyPort }],
				routes: [baseRoute()],
			}],
		});

		server = spawnServer(configPath, statusPath);
		await waitFor(() => fs.existsSync(statusPath));
	});

	after(async () => {
		await killServer(server);
		await echo.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('allows TLS connections before protection is added', async () => {
		const data = Buffer.from('before-protection');
		const res = await tlsRoundTrip({
			port: proxyPort,
			servername: 'localhost',
			caCert: cert.cert,
			data,
			rejectUnauthorized: true,
		});
		assert.deepEqual(res, data);
	});

	it('blocks connections after adding a protection blocklist — none→some forces recreate', async () => {
		// Adding a protection block to a listener that had none changes hasProtection in the
		// signature → server recreates the proxy with protection enabled, covering 127.0.0.1/32.
		writeConfigAtomic(configPath, {
			version: 1,
			proxies: [{
				listeners: [{ host: '127.0.0.1', port: proxyPort, protection: { blocklist: ['127.0.0.1/32'] } }],
				routes: [baseRoute()],
			}],
		});

		// Poll until TLS from 127.0.0.1 is rejected (blocked pre-handshake).
		await waitFor(
			async () => {
				try {
					await tlsRoundTrip({ port: proxyPort, servername: 'localhost', caCert: cert.cert, data: Buffer.from('p'), rejectUnauthorized: true });
					return false; // still allowed — recreate not picked up yet
				} catch {
					return true; // blocked
				}
			},
			8000, 150
		);
	});

	it('allows connections again after removing protection — some→none forces another recreate', async () => {
		writeConfigAtomic(configPath, {
			version: 1,
			proxies: [{
				listeners: [{ host: '127.0.0.1', port: proxyPort }], // no protection
				routes: [baseRoute()],
			}],
		});

		const data = Buffer.from('after-protection-removed');
		let res: Buffer | null = null;
		await waitFor(
			async () => {
				try {
					const r = await tlsRoundTrip({ port: proxyPort, servername: 'localhost', caCert: cert.cert, data, rejectUnauthorized: true });
					if (r.length === data.length && Buffer.compare(r, data) === 0) { res = r; return true; }
					return false;
				} catch { return false; }
			},
			8000, 150
		);
		assert.deepEqual(res, data, `traffic not unblocked. stderr:\n${server.getStderr()}`);
	});
});

describe('symphony-server (status.json ownership guard)', () => {
	// During a version upgrade the replacement starts first (SO_REUSEPORT overlap) and
	// rewrites status.json with its own pid before the incumbent retires. stop() must only
	// delete status.json if this process still owns it, or it clobbers the successor's file.
	const cert = generateSelfSignedCert('localhost');
	let dir: string;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-status-'));
		echo = await startEchoServer();
	});

	after(async () => {
		await echo.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	});

	// Inline cert (no cert files) so overwriting the status file can't trip a cert watcher
	// and cause a reconcile that rewrites status.json out from under the test.
	async function boot(name: string): Promise<{ server: RunningServer; statusPath: string }> {
		const configPath = path.join(dir, `${name}.json`);
		const statusPath = path.join(dir, `${name}-status.json`);
		const port = await getFreePort();
		writeConfigAtomic(configPath, {
			version: 1,
			proxies: [
				{
					listeners: [{ host: '127.0.0.1', port }],
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
		});
		const server = spawnServer(configPath, statusPath);
		await waitFor(() => fs.existsSync(statusPath));
		return { server, statusPath };
	}

	it('removes status.json on stop when this process owns it', async () => {
		const { server, statusPath } = await boot('owned');
		assert.equal(JSON.parse(fs.readFileSync(statusPath, 'utf8')).pid, server.child.pid);
		await killServer(server);
		assert.equal(fs.existsSync(statusPath), false, 'owned status.json should be removed on stop');
	});

	it('leaves status.json alone on stop when another process owns it', async () => {
		const { server, statusPath } = await boot('foreign');
		// A successor process overwrites status.json with its own pid before this one retires.
		const foreignPid = 2147483646;
		writeConfigAtomic(statusPath, { pid: foreignPid, note: 'successor' });
		await killServer(server);
		assert.equal(fs.existsSync(statusPath), true, 'a status.json owned by another pid must survive stop');
		assert.equal(
			JSON.parse(fs.readFileSync(statusPath, 'utf8')).pid,
			foreignPid,
			'the successor-owned status.json must be left untouched'
		);
	});
});

describe('symphony-server (construction-frozen proxy fields force a recreate)', () => {
	// readBufferSize, its two per-direction overrides, and lazyCopyBufferThreshold are all frozen
	// in SymphonyProxyWrap at construction — updateConfig() reaches none of them. If they were
	// missing from the reconcile's construction signature, editing one would leave the signature
	// unchanged, take the route-only hot-swap branch, and report a successful reload while the
	// proxy kept running the old value. Silent, and only ever visible as "the setting we shipped
	// didn't do anything".
	//
	// The observable is the server's own "proxy listening on ports" line, which the recreate
	// branch emits and the hot-swap branch does not. Note it is NOT connection loss: stop() ends
	// the accept loops but in-flight connection tasks run to completion, so established
	// connections survive a recreate and keep the old buffer sizes — which is exactly why the
	// README calls a buffer-size edit a reconnect event.
	//
	// The route-only case is the control. Without it this would pass equally well against a
	// server that recreated on every config write, which would prove nothing about the signature.
	const cert = generateSelfSignedCert('localhost');
	let dir: string;
	let configPath: string;
	let statusPath: string;
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let server: RunningServer;

	const LISTENING_LINE = /proxy listening on ports/g;
	const listenCount = () => (server.getStdout().match(LISTENING_LINE) ?? []).length;

	const baseConfig = (extra: Record<string, unknown>, routeSnis: string[] = ['localhost']) => ({
		version: 1,
		proxies: [
			{
				listeners: [{ host: '127.0.0.1', port: proxyPort }],
				routes: routeSnis.map((sni) => ({
					sni,
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				})),
				...extra,
			},
		],
	});

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-recreate-'));
		configPath = path.join(dir, 'config.json');
		statusPath = path.join(dir, 'status.json');
		echo = await startEchoServer();
		proxyPort = await getFreePort();
		writeConfigAtomic(configPath, baseConfig({ readBufferSize: 4096, lazyCopyBufferThreshold: 0 }));
		server = spawnServer(configPath);
		await waitFor(() => fs.existsSync(statusPath));
		await waitFor(() => listenCount() >= 1);
	});

	after(async () => {
		await killServer(server);
		await echo.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('recreates the proxy when lazyCopyBufferThreshold changes', async () => {
		const before = listenCount();
		writeConfigAtomic(configPath, baseConfig({ readBufferSize: 4096, lazyCopyBufferThreshold: 5000 }));
		await waitFor(() => listenCount() > before, 8000, 100);

		// Healthy on the new value, not merely torn down and rebuilt into nothing.
		const fresh = await tlsRoundTrip({ port: proxyPort, servername: 'localhost', caCert: cert.cert, data: Buffer.from('after-threshold'), rejectUnauthorized: false });
		assert.equal(fresh.toString(), 'after-threshold');
	});

	it('recreates the proxy when readBufferSize changes', async () => {
		const before = listenCount();
		writeConfigAtomic(configPath, baseConfig({ readBufferSize: 16384, lazyCopyBufferThreshold: 5000 }));
		await waitFor(() => listenCount() > before, 8000, 100);

		const fresh = await tlsRoundTrip({ port: proxyPort, servername: 'localhost', caCert: cert.cert, data: Buffer.from('after-bufsize'), rejectUnauthorized: false });
		assert.equal(fresh.toString(), 'after-bufsize');
	});

	it('leaves established connections running on the old proxy across a recreate', async () => {
		// Documents what a recreate actually does to in-flight sessions, which is NOT what the
		// mechanism suggests at a glance: stop() sends the shutdown broadcast (ending the accept
		// loops) and sleeps 100ms, but it never aborts connection tasks, and the tokio runtime
		// lives inside the napi wrap until JS garbage-collects it. So established sessions keep
		// running — on the OLD buffer settings — rather than being dropped.
		//
		// This matters most for exactly the deployment the setting targets: long-lived MQTT
		// subscribers would keep their old buffers indefinitely after an operator lowered the
		// value to reclaim memory.
		const held = await new Promise<tls.TLSSocket>((resolve, reject) => {
			const s = tls.connect(
				{ port: proxyPort, host: '127.0.0.1', servername: 'localhost', ca: cert.cert, rejectUnauthorized: false },
				() => resolve(s),
			);
			s.on('error', reject);
		});
		const echoOn = (payload: string) =>
			new Promise<string>((resolve, reject) => {
				const t = setTimeout(() => reject(new Error('no echo on held connection')), 3000);
				held.once('data', (d: Buffer) => {
					clearTimeout(t);
					resolve(d.toString());
				});
				held.write(payload);
			});

		assert.equal(await echoOn('pre-recreate'), 'pre-recreate');

		const before = listenCount();
		writeConfigAtomic(configPath, baseConfig({ readBufferSize: 32768, lazyCopyBufferThreshold: 5000 }));
		await waitFor(() => listenCount() > before, 8000, 100);

		assert.equal(held.destroyed, false, 'the held connection must survive the recreate');
		assert.equal(await echoOn('post-recreate'), 'post-recreate', 'and must still proxy on the old proxy');
		held.destroy();
	});

	it('hot-swaps instead of recreating for a route-only change (control)', async () => {
		const before = listenCount();
		// Same listeners, same proxy-level fields — only the route table grows, which is what the
		// hot-swap path exists for.
		writeConfigAtomic(configPath, baseConfig({ readBufferSize: 16384, lazyCopyBufferThreshold: 5000 }, ['localhost', 'other.localhost']));

		// The added route proving the reload really applied — otherwise "no recreate" would also
		// be satisfied by the server having ignored the edit entirely.
		await waitFor(async () => {
			try {
				const r = await tlsRoundTrip({ port: proxyPort, servername: 'other.localhost', caCert: cert.cert, data: Buffer.from('hi'), rejectUnauthorized: false });
				return r.toString() === 'hi';
			} catch {
				return false;
			}
		}, 8000, 100);

		assert.equal(listenCount(), before, `a route-only edit must hot-swap, not recreate. stdout:\n${server.getStdout()}`);
	});
});
