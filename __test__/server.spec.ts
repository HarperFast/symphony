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
import { generateSelfSignedCert, getFreePort, startEchoServer, tlsRoundTrip, sleep } from './util.js';

// server.js sits next to this compiled spec's sibling ts/ dir: dist-test/ts/server.js
const SERVER_JS = path.join(__dirname, '..', 'ts', 'server.js');

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
	markShutdown: () => void;
}

function spawnServer(configPath: string): RunningServer {
	let stderr = '';
	let shuttingDown = false;
	const child = spawn(process.execPath, [SERVER_JS, '--config', configPath], { stdio: ['ignore', 'pipe', 'pipe'] });
	child.stderr?.on('data', (d) => (stderr += d.toString()));
	child.on('exit', (code, sig) => {
		if (!shuttingDown) stderr += `\n[child exited early code=${code} sig=${sig}]`;
	});
	return { child, getStderr: () => stderr, markShutdown: () => (shuttingDown = true) };
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
		assert.equal(status.version, '0.4.0');
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
