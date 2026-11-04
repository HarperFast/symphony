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
import * as net from 'node:net';
import * as os from 'node:os';
import * as path from 'node:path';
import { generateClientCa, generateSelfSignedCert, getFreePort, startEchoServer, tlsRoundTrip, sleep } from './util.js';

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
	getStdout: () => string;
	getStderr: () => string;
	markShutdown: () => void;
}

function spawnServer(
	configPath: string,
	statusPath?: string,
	opts: { env?: NodeJS.ProcessEnv; cwd?: string; configFlag?: string } = {}
): RunningServer {
	let stdout = '';
	let stderr = '';
	let shuttingDown = false;
	const args = [SERVER_JS, opts.configFlag ?? '--config', configPath];
	if (statusPath) args.push('--status', statusPath);
	const child = spawn(process.execPath, args, {
		stdio: ['ignore', 'pipe', 'pipe'],
		env: { ...process.env, ...opts.env },
		cwd: opts.cwd,
	});
	child.stdout?.on('data', (d) => (stdout += d.toString()));
	child.stderr?.on('data', (d) => (stderr += d.toString()));
	child.on('exit', (code, sig) => {
		if (!shuttingDown) stderr += `\n[child exited early code=${code} sig=${sig}]`;
	});
	return { child, getStdout: () => stdout, getStderr: () => stderr, markShutdown: () => (shuttingDown = true) };
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

describe('symphony-server (a route that fails to rebuild never keeps an old client-cert policy)', () => {
	// symphony#62
	const serverCert = generateSelfSignedCert('tenant.local');
	const clientCa = generateClientCa();
	const client = { clientCert: clientCa.clientCert, clientKey: clientCa.clientKey };
	let dir: string;
	let configPath: string;
	let statusPath: string;
	let caFile: string;
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let server: RunningServer;

	// Each route reads its own copy of the cert/key, so deleting one route's file breaks only that route.
	const certFiles = (sni: string) => {
		const certChainFile = path.join(dir, `${sni}.crt`);
		const privateKeyFile = path.join(dir, `${sni}.key`);
		return { certChainFile, privateKeyFile };
	};
	const route = (sni: string, mtls?: object) => ({
		sni,
		upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
		terminateTls: true,
		cert: certFiles(sni),
		mtls,
	});
	const publish = (open: object) =>
		writeConfigAtomic(configPath, {
			version: 1,
			proxies: [
				{
					listeners: [{ host: '127.0.0.1', port: proxyPort }],
					routes: [
						open,
						route('inline-ca.local', { clientCaCert: clientCa.caCert, requireClientCert: true }),
						route('file-ca.local', { clientCaCertFile: caFile, requireClientCert: true }),
						// No client auth: a dropped route under it must not fall through to it.
						route('*.local'),
					],
				},
			],
		});
	const connects = async (servername: string, presented: Partial<typeof client> = {}) => {
		try {
			const reply = await tlsRoundTrip({ port: proxyPort, servername, data: Buffer.from('ping'), ...presented });
			return reply.toString() === 'ping';
		} catch {
			return false;
		}
	};
	const reloadedAt = (): string => {
		try {
			return JSON.parse(fs.readFileSync(statusPath, 'utf8')).reloadedAt ?? '';
		} catch {
			return '';
		}
	};
	const becomesRefused = (servername: string, presented: Partial<typeof client> = {}) =>
		waitFor(async () => !(await connects(servername, presented)), 8000, 150).then(
			() => true,
			() => false
		);

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-clientauth-'));
		configPath = path.join(dir, 'config.json');
		statusPath = path.join(dir, 'status.json');
		caFile = path.join(dir, 'client-ca.pem');
		fs.writeFileSync(caFile, clientCa.caCert);
		for (const sni of ['open.local', 'inline-ca.local', 'file-ca.local', '*.local']) {
			fs.writeFileSync(certFiles(sni).certChainFile, serverCert.cert);
			fs.writeFileSync(certFiles(sni).privateKeyFile, serverCert.key);
		}

		echo = await startEchoServer();
		proxyPort = await getFreePort();
		publish(route('open.local'));
		server = spawnServer(configPath, statusPath);
		await waitFor(() => fs.existsSync(statusPath));
	});

	after(async () => {
		await killServer(server);
		await echo.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	});

	it('drops a route republished to require client certs under a CA no verifier can use', async () => {
		await waitFor(() => connects('open.local'));
		publish(route('open.local', { clientCaCert: '', requireClientCert: true }));
		assert.ok(
			await becomesRefused('open.local'),
			'a certless client still reaches the route reloaded to require certs'
		);
		assert.match(server.getStderr(), /route 'open\.local'.*not retained/);
		assert.equal(server.child.exitCode, null);
		assert.equal(await connects('other.local'), true, 'the wildcard keeps serving its own subdomains');
	});

	it('drops a route whose client CA file becomes unreadable', async () => {
		await waitFor(() => connects('file-ca.local', client));
		fs.rmSync(caFile);
		assert.ok(await becomesRefused('file-ca.local', client), 'the route kept trusting a CA it can no longer read');
		assert.match(server.getStderr(), /route 'file-ca\.local'.*not retained/);
		assert.equal(await connects('inline-ca.local', client), true, 'a co-tenant keeps serving');

		fs.writeFileSync(caFile, clientCa.caCert);
		await waitFor(() => connects('file-ca.local', client), 8000, 150);
		assert.equal(await connects('file-ca.local'), false, 'the restored route requires a client cert again');
	});

	it('keeps the last-good route of an mTLS route whose cert file goes missing', async () => {
		await waitFor(() => connects('inline-ca.local', client));
		fs.rmSync(certFiles('inline-ca.local').privateKeyFile);
		// status.json's reloadedAt is written once that reconcile has published its table.
		const unreadable = /^(\S+) \[symphony-server\] failed to resolve cert material for route 'inline-ca\.local'/m;
		await waitFor(() => unreadable.test(server.getStderr()), 8000, 100);
		const loggedAt = server.getStderr().match(unreadable)![1];
		await waitFor(() => reloadedAt() >= loggedAt, 8000, 50);
		assert.equal(await connects('inline-ca.local', client), true, `stderr:\n${server.getStderr()}`);
		assert.equal(await connects('inline-ca.local'), false, 'the retained route still requires a client cert');
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
	// rewrites status.json with its own pid before the incumbent retires. The file must name the
	// newest live process throughout, and stop() never deletes it.
	const cert = generateSelfSignedCert('localhost');
	let dir: string;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	const peers: ChildProcess[] = [];

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-status-'));
		echo = await startEchoServer();
	});

	after(async () => {
		for (const peer of peers) peer.kill('SIGKILL');
		await echo.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	});

	// Inline cert (no cert files) so overwriting the status file can't trip a cert watcher
	// and cause a reconcile that rewrites status.json out from under the test.
	async function boot(name: string): Promise<{ server: RunningServer; configPath: string; statusPath: string }> {
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
		// SIGHUP is only handled once start() has returned, which is after this line is logged.
		await waitFor(() => server.getStdout().includes('watching'));
		return { server, configPath, statusPath };
	}

	// Stands in for another symphony-server: a live process started with `--config <configPath>`.
	function startPeer(configPath: string): number {
		const script = 'setInterval(() => {}, 1 << 30)';
		const peer = spawn(process.execPath, ['-e', script, 'symphony-peer', '--config', configPath], { stdio: 'ignore' });
		peers.push(peer);
		return peer.pid!;
	}

	const statusPid = (statusPath: string): number | undefined => JSON.parse(fs.readFileSync(statusPath, 'utf8'))?.pid;

	it('does not repoint status.json at itself on reload while a newer live peer owns it', async () => {
		const { server, configPath, statusPath } = await boot('newer-peer');
		const peerPid = startPeer(configPath);
		writeConfigAtomic(statusPath, { pid: peerPid, startedAt: new Date().toISOString() });

		server.child.kill('SIGHUP');
		await waitFor(() => server.getStdout().includes(`status.json belongs to newer pid ${peerPid}`));

		await sleep(1500); // past the first post-write recheck
		assert.equal(statusPid(statusPath), peerPid);
		await killServer(server);
		assert.equal(statusPid(statusPath), peerPid, "stop() leaves the successor's status.json in place");
	});

	it('takes status.json back when the newer peer it yielded to exits', async () => {
		const { server, configPath, statusPath } = await boot('successor-exits');
		const peerPid = startPeer(configPath);
		writeConfigAtomic(statusPath, { pid: peerPid, startedAt: new Date().toISOString() });
		server.child.kill('SIGHUP');
		await waitFor(() => server.getStdout().includes(`status.json belongs to newer pid ${peerPid}`));
		await sleep(1500); // past the startup write's first recheck, which would otherwise reclaim it

		process.kill(peerPid, 'SIGKILL');

		await waitFor(() => statusPid(statusPath) === server.child.pid, 12_000);
		await killServer(server);
	});

	// A 1.3.0 incumbent has no writeStatus guard, and its reload of the config write that preceded this
	// process's start lands ~300ms after it.
	it('takes status.json back from an older process that overwrites it after this one wrote it', async () => {
		const { server, configPath, statusPath } = await boot('overwritten');
		writeConfigAtomic(statusPath, { pid: startPeer(configPath), startedAt: new Date(0).toISOString() });

		await waitFor(() => statusPid(statusPath) === server.child.pid, 5000);
		await killServer(server);
	});

	for (const [name, owner, makeOwner] of [
		[
			'dead-newer',
			'a newer pid that is no longer running',
			() => ({ pid: 2147483646, startedAt: new Date().toISOString() }),
		],
		[
			'older-peer',
			'an older live peer',
			(configPath: string) => ({ pid: startPeer(configPath), startedAt: new Date(0).toISOString() }),
		],
		['null-status', 'a status.json holding JSON null', () => null],
	] as const) {
		it(`reclaims status.json on reload from ${owner}`, async () => {
			const { server, configPath, statusPath } = await boot(name);
			writeConfigAtomic(statusPath, makeOwner(configPath));

			server.child.kill('SIGHUP');
			await waitFor(() => statusPid(statusPath) === server.child.pid);
			await killServer(server);
		});
	}

	it(
		'reclaims status.json from a newer live pid that is not serving this config',
		{ skip: process.platform !== 'linux' && '/proc cmdline check is Linux-only' },
		async () => {
			const { server, configPath, statusPath } = await boot('recycled-pid');
			writeConfigAtomic(statusPath, { pid: startPeer(`${configPath}.other`), startedAt: new Date().toISOString() });

			server.child.kill('SIGHUP');
			await waitFor(() => statusPid(statusPath) === server.child.pid);
			await killServer(server);
		}
	);

	it('leaves status.json in place on stop, naming the exited pid', async () => {
		const { server, statusPath } = await boot('owned');
		const pid = server.child.pid;
		assert.equal(statusPid(statusPath), pid);
		await killServer(server);
		assert.equal(statusPid(statusPath), pid, 'a supervisor reads the dead pid as not running');
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

describe(
	'symphony-server (an older process stands down for a newer one on the same config)',
	{
		skip: process.platform !== 'linux' && 'standing down needs /proc to verify the successor',
	},
	() => {
		const POLL_MS = 50;
		const GRACE_MS = 1000;
		const env = { SYMPHONY_STATUS_POLL_MS: String(POLL_MS), SYMPHONY_SUPERSEDE_GRACE_MS: String(GRACE_MS) };
		const cert = generateSelfSignedCert('localhost');
		let dir: string;
		let echo: Awaited<ReturnType<typeof startEchoServer>>;
		const servers: RunningServer[] = [];
		const peers: ChildProcess[] = [];

		before(async () => {
			dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-stand-down-'));
			echo = await startEchoServer();
		});

		after(async () => {
			for (const server of servers) await killServer(server);
			for (const peer of peers) peer.kill('SIGKILL');
			await echo.close().catch(() => {});
			fs.rmSync(dir, { recursive: true, force: true });
		});

		interface Setup {
			name: string;
			configPath: string;
			statusPath: string;
			port: number;
		}

		async function writeConfig(name: string, extraProxies: unknown[] = []): Promise<Setup> {
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
					...extraProxies,
				],
			});
			return { name, configPath, statusPath, port };
		}

		async function launch(
			setup: Setup,
			opts: { cwd?: string; configFlag?: string; configArg?: string } = {}
		): Promise<RunningServer> {
			const server = spawnServer(opts.configArg ?? setup.configPath, setup.statusPath, {
				env,
				cwd: opts.cwd,
				configFlag: opts.configFlag,
			});
			servers.push(server);
			await waitFor(() => status(setup)?.pid === server.child.pid);
			await waitFor(() => server.getStdout().includes('watching'));
			return server;
		}

		const status = (setup: Setup): { pid: number; listeners?: string[] } | null => {
			try {
				return JSON.parse(fs.readFileSync(setup.statusPath, 'utf8'));
			} catch {
				return null;
			}
		};
		const running = (server: RunningServer): boolean =>
			server.child.exitCode === null && server.child.signalCode === null;
		const roundTrip = (port: number) => tlsRoundTrip({ port, servername: 'localhost', data: Buffer.from('ping') });

		it('exits after the grace once a newer process serves the same config, leaving it status.json', async () => {
			const setup = await writeConfig('handoff');
			// Relative --config / -c on both sides: they still recognise each other as serving one config.
			const incumbent = await launch(setup, { cwd: dir, configArg: 'handoff.json' });
			const successor = await launch(setup, { cwd: dir, configFlag: '-c', configArg: './handoff.json' });
			const claimedAt = Date.now();
			assert.deepEqual(status(setup)?.listeners, [`127.0.0.1:${setup.port}`]);

			await waitFor(() => !running(incumbent), GRACE_MS * 5);
			const elapsed = Date.now() - claimedAt;
			assert.ok(elapsed >= GRACE_MS - POLL_MS, `stood down after ${elapsed} ms, before the ${GRACE_MS} ms grace`);
			incumbent.markShutdown();
			assert.equal(incumbent.child.exitCode, 0);
			assert.match(incumbent.getStdout(), new RegExp(`superseded by pid ${successor.child.pid}, shutting down`));
			assert.equal(status(setup)?.pid, successor.child.pid, 'the retiring process leaves status.json alone');
			assert.equal((await roundTrip(setup.port)).toString(), 'ping', 'the successor serves the port');
			assert.ok(running(successor));
		});

		it('keeps serving and takes status.json back when the successor dies during the grace', async () => {
			const setup = await writeConfig('successor-dies');
			const incumbent = await launch(setup);
			const successor = await launch(setup);
			await waitFor(() => incumbent.getStdout().includes(`pid ${successor.child.pid} serves this config`));

			successor.markShutdown();
			successor.child.kill('SIGKILL');

			await waitFor(() => status(setup)?.pid === incumbent.child.pid, GRACE_MS);
			await sleep(GRACE_MS * 2);
			assert.ok(running(incumbent), incumbent.getStdout());
			assert.equal((await roundTrip(setup.port)).toString(), 'ping');
		});

		it('stops normally on SIGTERM during the grace', async () => {
			const setup = await writeConfig('sigterm-in-grace');
			const incumbent = await launch(setup);
			const successor = await launch(setup);
			await waitFor(() => incumbent.getStdout().includes(`pid ${successor.child.pid} serves this config`));

			await killServer(incumbent);
			assert.equal(incumbent.child.exitCode, 0);
			assert.match(incumbent.getStdout(), /received SIGTERM, shutting down/);
			assert.doesNotMatch(incumbent.getStdout(), /superseded/);
			assert.equal(status(setup)?.pid, successor.child.pid);
		});

		it('ignores a newer process serving a different config through the same status file', async () => {
			const setup = await writeConfig('own-config');
			const other = await writeConfig('other-config');
			const incumbent = await launch(setup);
			const stranger = spawnServer(other.configPath, setup.statusPath, { env });
			servers.push(stranger);
			await waitFor(() => stranger.getStdout().includes('watching'));

			await sleep(GRACE_MS * 2);
			assert.ok(running(incumbent), incumbent.getStdout());
			assert.doesNotMatch(incumbent.getStdout(), /superseded|serves this config/);
		});

		it('does not stand down for a stopped successor, and takes status.json back from it', async () => {
			const setup = await writeConfig('stopped-successor');
			const incumbent = await launch(setup);
			const successor = await launch(setup);
			await waitFor(() => incumbent.getStdout().includes(`pid ${successor.child.pid} serves this config`));

			successor.child.kill('SIGSTOP');
			try {
				await waitFor(() => status(setup)?.pid === incumbent.child.pid, GRACE_MS);
				await sleep(GRACE_MS * 2);
				assert.ok(running(incumbent), incumbent.getStdout());
			} finally {
				successor.child.kill('SIGCONT');
			}
		});

		it('does not claim status.json from a 1.4 owner listing a port it lacks', async () => {
			const setup = await writeConfig('legacy-owner');
			const server = await launch(setup);
			const legacyPeer = startPeer(setup.configPath);
			writeConfigAtomic(setup.statusPath, {
				pid: legacyPeer,
				version: '1.4.0',
				startedAt: new Date(0).toISOString(),
				configPath: setup.configPath,
				ports: [setup.port, 1],
			});

			await waitFor(() =>
				server
					.getStdout()
					.includes(`not taking status.json: pid ${legacyPeer} listens on port 1, which this process does not`)
			);
			assert.equal(status(setup)?.pid, legacyPeer);
		});

		it('a newer process missing one of its listeners does not claim status.json from it', async () => {
			const keyFile = path.join(dir, 'listener-key.pem');
			fs.writeFileSync(keyFile, cert.key);
			const secondPort = await getFreePort();
			const setup = await writeConfig('partial', [
				{
					listeners: [
						{ host: '127.0.0.1', port: secondPort, defaultCert: { certChain: cert.cert, privateKeyFile: keyFile } },
					],
					routes: [
						{ sni: 'localhost', upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }], terminateTls: true },
					],
				},
			]);
			const incumbent = await launch(setup);
			assert.equal(status(setup)?.listeners?.length, 2);
			// The successor can't build that listener; the incumbent keeps the one it already has.
			fs.rmSync(keyFile);
			const successor = spawnServer(setup.configPath, setup.statusPath, { env });
			servers.push(successor);

			await waitFor(() =>
				successor
					.getStdout()
					.includes(
						`not taking status.json: pid ${incumbent.child.pid} listens on 127.0.0.1:${secondPort}, which this process does not`
					)
			);
			await sleep(GRACE_MS * 2);
			assert.equal(status(setup)?.pid, incumbent.child.pid, 'a supervisor never sees the successor as ready');
			assert.ok(running(incumbent), incumbent.getStdout());
		});

		// A live process started with `--config <configPath>` that publishes a qualifying status, so the
		// test controls exactly when the file names it.
		function startPeer(configPath: string): number {
			const peer = spawn(
				process.execPath,
				['-e', 'setInterval(() => {}, 1 << 30)', 'symphony-peer', '--config', configPath],
				{
					stdio: 'ignore',
				}
			);
			peers.push(peer);
			return peer.pid!;
		}

		it('restarts the grace when status.json comes back to it in between', async () => {
			const setup = await writeConfig('interrupted');
			const incumbent = await launch(setup);
			const own = status(setup)!;
			const successor = {
				pid: startPeer(setup.configPath),
				startedAt: new Date().toISOString(),
				configPath: setup.configPath,
				listeners: own.listeners,
			};

			writeConfigAtomic(setup.statusPath, successor);
			await waitFor(() => incumbent.getStdout().includes(`pid ${successor.pid} serves this config`));
			await sleep(GRACE_MS * 0.6);
			writeConfigAtomic(setup.statusPath, own);
			await sleep(POLL_MS * 4);
			writeConfigAtomic(setup.statusPath, successor);
			await sleep(GRACE_MS * 0.6);
			assert.ok(running(incumbent), 'the two tenures together exceed the grace, but neither alone does');

			await waitFor(() => !running(incumbent), GRACE_MS * 3);
			incumbent.markShutdown();
			assert.match(incumbent.getStdout(), new RegExp(`superseded by pid ${successor.pid}`));
		});

		it('does not stand down for a newer owner that is not listening on all of its listeners', async () => {
			const setup = await writeConfig('uncovered');
			const incumbent = await launch(setup);
			const successor = {
				pid: startPeer(setup.configPath),
				startedAt: new Date().toISOString(),
				configPath: setup.configPath,
				listeners: [],
			};
			writeConfigAtomic(setup.statusPath, successor);

			await waitFor(() =>
				incumbent
					.getStdout()
					.includes(`not standing down for pid ${successor.pid}: it is not listening on 127.0.0.1:${setup.port}`)
			);
			await sleep(GRACE_MS * 2);
			assert.ok(running(incumbent), incumbent.getStdout());
		});
	}
);

describe('symphony-server (config generation)', () => {
	const cert = generateSelfSignedCert('localhost');
	let dir: string;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let deadPort: number;
	const servers: RunningServer[] = [];
	const peers: ChildProcess[] = [];

	before(async () => {
		dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-generation-'));
		echo = await startEchoServer();
		deadPort = await getFreePort();
	});

	after(async () => {
		for (const peer of peers) peer.kill('SIGKILL');
		await Promise.all(servers.map(killServer));
		await echo.close().catch(() => {});
		fs.rmSync(dir, { recursive: true, force: true });
	});

	// Inline certs, so a cert watcher only runs where a test references a file.
	function entry(port: number, opts: { upstream?: number; listener?: object; proxy?: object } = {}): object {
		return {
			listeners: [{ host: '127.0.0.1', port, ...opts.listener }],
			routes: [
				{
					sni: 'localhost',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: opts.upstream ?? echo.port }],
					terminateTls: true,
					cert: { certChain: cert.cert, privateKey: cert.key },
				},
			],
			...opts.proxy,
		};
	}

	async function boot(name: string, config: unknown, env?: NodeJS.ProcessEnv) {
		const configPath = path.join(dir, `${name}.json`);
		const statusPath = path.join(dir, `${name}-status.json`);
		writeConfigAtomic(configPath, config);
		const server = spawnServer(configPath, statusPath, { env });
		servers.push(server);
		await waitFor(() => fs.existsSync(statusPath));
		await waitFor(() => server.getStdout().includes('watching'));
		const status = () => JSON.parse(fs.readFileSync(statusPath, 'utf8'));
		// Writes a config and waits for the reconcile of it to publish, whatever it reports.
		const apply = async (next: unknown) => {
			const { reloadedAt } = status();
			writeConfigAtomic(configPath, next);
			await waitFor(() => status().reloadedAt !== reloadedAt, 5000, 20);
			return status();
		};
		return { server, configPath, statusPath, status, apply };
	}

	function reaches(port: number): Promise<boolean> {
		const data = Buffer.from('ping');
		return tlsRoundTrip({ port, servername: 'localhost', caCert: cert.cert, data, rejectUnauthorized: true }).then(
			(reply) => reply.equals(data),
			() => false
		);
	}

	it('reports the config a reconcile read when it finishes after a newer write, and holds the newer one back', async () => {
		// Parks each SymphonyProxy.start() behind a file while leaving the event loop free, so a
		// reconcile that overlapped this one would reach start() rather than wait in the chain.
		const gate = path.join(dir, 'gate');
		fs.mkdirSync(gate);
		const preload = path.join(gate, 'preload.js');
		fs.writeFileSync(
			preload,
			`const fs = require('node:fs');
			const { SymphonyProxy } = require(${JSON.stringify(path.join(__dirname, '..', 'ts', 'proxy.js'))});
			const gate = ${JSON.stringify(gate)};
			const { start } = SymphonyProxy.prototype;
			let calls = 0;
			SymphonyProxy.prototype.start = async function () {
				if (fs.existsSync(gate + '/armed')) {
					const call = ++calls;
					fs.writeFileSync(gate + '/entered-' + call, '');
					while (!fs.existsSync(gate + '/release-' + call)) await new Promise((r) => setTimeout(r, 10));
				}
				return start.apply(this);
			};`
		);
		const entered = (call: number) => fs.existsSync(path.join(gate, `entered-${call}`));
		const release = (call: number) => fs.writeFileSync(path.join(gate, `release-${call}`), '');

		const port = await getFreePort();
		// A construction-frozen setting changes each time, so every reconcile recreates and reaches start().
		const config = (generation: string, readBufferSize: number) => ({
			generation,
			proxies: [entry(port, { proxy: { readBufferSize } })],
		});
		const { server, configPath, status } = await boot('gate', config('boot', 16384), {
			NODE_OPTIONS: `--require ${preload}`,
		});
		fs.writeFileSync(path.join(gate, 'armed'), '');

		writeConfigAtomic(configPath, config('read', 32768));
		await waitFor(() => entered(1));

		writeConfigAtomic(configPath, config('written', 65536));
		const writtenAt = Date.now();
		server.child.kill('SIGHUP');
		await sleep(500); // past the watcher's debounce too
		assert.equal(entered(2), false, 'a reconcile started while another was running');
		assert.equal(status().appliedGeneration, 'boot');

		release(1);
		await waitFor(() => status().appliedGeneration !== 'boot');
		const acknowledged = status();
		assert.equal(acknowledged.appliedGeneration, 'read');
		assert.ok(
			Date.parse(acknowledged.reloadedAt) >= writtenAt,
			'reloadedAt alone would read as acknowledging the write'
		);

		await waitFor(() => entered(2));
		assert.equal(status().appliedGeneration, 'read');
		release(2);
		await waitFor(() => status().appliedGeneration === 'written');
	});

	it('keeps appliedGeneration when a proxy is skipped, reports its ports, and clears once it applies', async () => {
		const [healthy, skipped] = [await getFreePort(), await getFreePort()];
		const certDir = path.join(dir, 'skipped-certs');
		fs.mkdirSync(certDir);
		const keyFile = path.join(certDir, 'key.pem');
		const { status, apply } = await boot('skipped', {
			generation: 'g1',
			proxies: [entry(healthy, { upstream: deadPort }), entry(skipped)],
		});
		assert.equal(status().appliedGeneration, 'g1');
		assert.equal(status().failedGeneration, undefined);
		assert.equal(await reaches(healthy), false);

		const before = status();
		const g2 = {
			generation: 'g2',
			proxies: [
				entry(healthy),
				entry(skipped, { listener: { defaultCert: { certChain: cert.cert, privateKeyFile: keyFile } } }),
			],
		};
		const failed = await apply(g2);
		assert.equal(failed.appliedGeneration, 'g1');
		assert.deepEqual(failed.failedGeneration, { generation: 'g2', ports: [skipped] });
		assert.notEqual(failed.reloadedAt, before.reloadedAt);
		assert.equal(await reaches(healthy), true, 'the other proxy takes the new config');
		assert.equal(await reaches(skipped), true, 'the skipped proxy keeps serving');

		// Same generation, no config write: the key file appearing is what triggers the retry.
		fs.writeFileSync(keyFile, cert.key);
		await waitFor(() => status().appliedGeneration === 'g2', 8000);
		assert.equal(status().failedGeneration, undefined);

		const reappliedAfterFailure = await apply({ generation: 'g3', proxies: g2.proxies });
		assert.equal(reappliedAfterFailure.appliedGeneration, 'g3');
	});

	it('names one generation in both fields when a reconcile re-reads an applied config and a proxy fails', async () => {
		const port = await getFreePort();
		const certDir = path.join(dir, 'reread-certs');
		fs.mkdirSync(certDir);
		const keyFile = path.join(certDir, 'key.pem');
		fs.writeFileSync(keyFile, cert.key);
		const { status } = await boot('reread', {
			generation: 'g1',
			proxies: [entry(port, { listener: { defaultCert: { certChain: cert.cert, privateKeyFile: keyFile } } })],
		});
		assert.equal(status().appliedGeneration, 'g1');

		fs.rmSync(keyFile);
		await waitFor(() => status().failedGeneration !== undefined, 8000);
		assert.equal(status().appliedGeneration, 'g1');
		assert.deepEqual(status().failedGeneration, { generation: 'g1', ports: [port] });
	});

	it('reports every skipped port once, in order', async () => {
		const [low, high] = [await getFreePort(), await getFreePort()].sort((a, b) => a - b);
		const unreadable = { defaultCert: { certChain: cert.cert, privateKeyFile: path.join(dir, 'absent.pem') } };
		const { status } = await boot('ports', {
			generation: 'g1',
			proxies: [
				{
					...entry(high),
					listeners: [
						{ host: '127.0.0.1', port: high, ...unreadable },
						{ host: '127.0.0.2', port: high, ...unreadable },
					],
				},
				entry(low, { listener: unreadable }),
			],
		});
		assert.equal(status().appliedGeneration, undefined, 'nothing has been applied yet');
		assert.deepEqual(status().failedGeneration, { generation: 'g1', ports: [low, high] });
	});

	it('reports a listener that cannot bind', async () => {
		const held = await getFreePort();
		const blocker = net.createServer();
		await new Promise<void>((resolve) => blocker.listen(held, '127.0.0.1', resolve));
		const proxyPort = await getFreePort();
		const { server, status, apply } = await boot('bind', { generation: 'g1', proxies: [entry(proxyPort)] });

		const failed = await apply({ generation: 'g2', proxies: [entry(proxyPort), entry(held)] });
		assert.equal(failed.appliedGeneration, 'g1');
		assert.deepEqual(failed.failedGeneration, { generation: 'g2', ports: [held] });

		await new Promise((resolve) => blocker.close(resolve));
		server.child.kill('SIGHUP');
		await waitFor(() => status().appliedGeneration === 'g2');
		assert.equal(status().failedGeneration, undefined);
	});

	it('reports a hot swap the proxy rejects', async () => {
		const port = await getFreePort();
		const protection = (ja3Blocklist: string[]) => ({ listener: { protection: { ja3Blocklist } } });
		const { apply } = await boot('hot-swap', { generation: 'g1', proxies: [entry(port, protection([]))] });

		const failed = await apply({ generation: 'g2', proxies: [entry(port, protection(['not-a-fingerprint']))] });
		assert.equal(failed.appliedGeneration, 'g1');
		assert.deepEqual(failed.failedGeneration, { generation: 'g2', ports: [port] });

		const applied = await apply({ generation: 'g3', proxies: [entry(port, protection([]))] });
		assert.equal(applied.appliedGeneration, 'g3');
		assert.equal(applied.failedGeneration, undefined);
	});

	it('reports a malformed entry as a skip and removes no running proxy on its account', async () => {
		const [named, unnamed] = [await getFreePort(), await getFreePort()];
		const { apply } = await boot('malformed', {
			generation: 'g1',
			proxies: [entry(named, { upstream: deadPort }), entry(unnamed)],
		});

		for (const [generation, malformed] of [
			['g2', { routes: [] }],
			['g3', null],
			['g4', { listeners: [null], routes: [] }],
		] as const) {
			const failed = await apply({ generation, proxies: [malformed, entry(named)] });
			assert.equal(failed.appliedGeneration, 'g1');
			assert.deepEqual(failed.failedGeneration, { generation, ports: [] });
			assert.equal(await reaches(named), true, 'a well-formed entry still applies');
			assert.equal(await reaches(unnamed), true, 'a running proxy the malformed entry may have meant stays up');
		}

		const applied = await apply({ generation: 'g5', proxies: [entry(named)] });
		assert.equal(applied.appliedGeneration, 'g5');
		assert.equal(await reaches(unnamed), false, 'removal resumes once every entry names its ports');
	});

	it('still reports when a path outside the per-proxy guard is unusable', async () => {
		const [healthy, skipped] = [await getFreePort(), await getFreePort()];
		const { server, apply } = await boot('bad-paths', { generation: 'g1', proxies: [entry(healthy), entry(skipped)] });

		const failed = await apply({
			generation: 'g2',
			admin: { socketPath: 17 },
			proxies: [
				entry(healthy),
				entry(skipped, { listener: { defaultCert: { certChainFile: 17, privateKey: cert.key } } }),
			],
		});
		assert.deepEqual(failed.failedGeneration, { generation: 'g2', ports: [skipped] });
		assert.match(server.getStderr(), /cert watcher update failed/);
		assert.match(server.getStderr(), /admin endpoint update failed/);
	});

	it('leaves status.json as it was without a generation, and clears both fields when one is dropped', async () => {
		const port = await getFreePort();
		const bareKeys = ['configPath', 'listeners', 'pid', 'ports', 'reloadedAt', 'startedAt', 'version'];
		const { status, apply } = await boot('none', { proxies: [entry(port)] });
		assert.deepEqual(Object.keys(status()).sort(), bareKeys);

		assert.equal((await apply({ generation: 'g1', proxies: [entry(port)] })).appliedGeneration, 'g1');

		const absent = path.join(dir, 'absent.pem');
		const unreadable = { listener: { defaultCert: { certChain: cert.cert, privateKeyFile: absent } } };
		const failed = await apply({ generation: 'g2', proxies: [entry(port), entry(await getFreePort(), unreadable)] });
		assert.notEqual(failed.failedGeneration, undefined);

		assert.deepEqual(Object.keys(await apply({ proxies: [entry(port)] })).sort(), bareKeys);
	});

	it('treats an unusable generation as none, and still applies the config', async () => {
		const port = await getFreePort();
		const { server, apply } = await boot('unusable', {
			generation: 'g1',
			proxies: [entry(port, { upstream: deadPort })],
		});

		let upstream = deadPort;
		for (const generation of [7, '', null, { nested: true }]) {
			upstream = upstream === deadPort ? echo.port : deadPort;
			const status = await apply({ generation, proxies: [entry(port, { upstream })] });
			assert.equal('appliedGeneration' in status, false, `generation ${JSON.stringify(generation)}`);
			assert.equal('failedGeneration' in status, false, `generation ${JSON.stringify(generation)}`);
			assert.equal(await reaches(port), upstream === echo.port, `generation ${JSON.stringify(generation)}`);
		}
		assert.match(server.getStderr(), /"generation" is not a non-empty string/);
	});

	it('applies a generation with no proxies at all', async () => {
		const port = await getFreePort();
		const { apply } = await boot('empty', { generation: 'g1', proxies: [entry(port)] });
		const applied = await apply({ generation: 'g2', proxies: [] });
		assert.equal(applied.appliedGeneration, 'g2');
		assert.deepEqual(applied.ports, []);
	});

	it('moves neither field when no config could be read', async () => {
		const port = await getFreePort();
		const absent = path.join(dir, 'absent.pem');
		const unreadable = { listener: { defaultCert: { certChain: cert.cert, privateKeyFile: absent } } };
		const { server, configPath, status, apply } = await boot('unread', { generation: 'g1', proxies: [entry(port)] });
		await apply({ generation: 'g2', proxies: [entry(port), entry(await getFreePort(), unreadable)] });
		const before = status();
		assert.equal(before.appliedGeneration, 'g1');
		assert.equal(before.failedGeneration.generation, 'g2');

		fs.writeFileSync(configPath, '{"generation": "g3", ');
		await waitFor(() => server.getStderr().includes('config is not valid JSON'));
		assert.deepEqual(status(), before);

		writeConfigAtomic(configPath, { generation: 'g3', proxies: 'none' });
		await waitFor(() => server.getStderr().includes('config has no "proxies" array'));
		assert.deepEqual(status(), before);
	});

	it('publishes a status write that failed, without another reconcile', async () => {
		const port = await getFreePort();
		const { server, statusPath, status, configPath } = await boot(
			'write-failure',
			{ generation: 'g1', proxies: [entry(port)] },
			{ SYMPHONY_STATUS_POLL_MS: '50' }
		);
		const tmp = `${statusPath}.${server.child.pid}.tmp`;
		fs.mkdirSync(tmp); // the writer's temp path, so its write fails and the previous document stays

		writeConfigAtomic(configPath, { generation: 'g2', proxies: [entry(port)] });
		await waitFor(() => server.getStderr().includes('could not write status'));
		assert.equal(status().appliedGeneration, 'g1');

		fs.rmdirSync(tmp);
		await waitFor(() => status().appliedGeneration === 'g2');
	});

	it('publishes the generation it applied while yielded once it takes status.json back', async () => {
		const port = await getFreePort();
		const { server, configPath, statusPath, status } = await boot(
			'yield',
			{ generation: 'g1', proxies: [entry(port)] },
			{ SYMPHONY_STATUS_POLL_MS: '50' }
		);
		const script = 'setInterval(() => {}, 1 << 30)';
		const peer = spawn(process.execPath, ['-e', script, 'symphony-peer', '--config', configPath], { stdio: 'ignore' });
		peers.push(peer);
		writeConfigAtomic(statusPath, { pid: peer.pid, startedAt: new Date().toISOString() });

		writeConfigAtomic(configPath, { generation: 'g2', proxies: [entry(port)] });
		await waitFor(() => server.getStdout().includes(`status.json belongs to newer pid ${peer.pid}`));
		await sleep(500); // past the debounce, so the reconcile of g2 has run while yielded
		assert.equal(status().pid, peer.pid);
		assert.equal(status().appliedGeneration, undefined);

		peer.kill('SIGKILL');
		await waitFor(() => status().pid === server.child.pid);
		assert.equal(status().appliedGeneration, 'g2');
	});

	it('a generation acknowledged with a drain means new connections already go to the peer', async () => {
		const hits = { local: 0, peer: 0 };
		const upstream = (name: keyof typeof hits) => {
			const server = net.createServer((socket) => {
				hits[name]++;
				socket.pipe(socket);
			});
			return new Promise<net.Server>((resolve) => server.listen(0, '127.0.0.1', () => resolve(server)));
		};
		const local = await upstream('local');
		const remote = await upstream('peer');
		const portOf = (server: net.Server) => (server.address() as net.AddressInfo).port;
		const [publicPort, ingressPort] = [await getFreePort(), await getFreePort()];
		const config = (generation: string, drain: boolean) => ({
			generation,
			proxies: [
				{
					listeners: [{ host: '127.0.0.1', port: publicPort }],
					routes: [
						{
							sni: 'localhost',
							upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: portOf(local) }],
							terminateTls: true,
							cert: { certChain: cert.cert, privateKey: cert.key },
							failover: { peers: [{ host: '127.0.0.1', port: ingressPort }], drain },
						},
					],
				},
				entry(ingressPort, {
					upstream: portOf(remote),
					listener: { failoverIngress: { trustedSources: ['127.0.0.1/32'] } },
				}),
			],
		});
		const { apply } = await boot('drain', config('serving', false));
		try {
			assert.equal(await reaches(publicPort), true);
			assert.deepEqual(hits, { local: 1, peer: 0 });

			assert.equal((await apply(config('draining', true))).appliedGeneration, 'draining');
			assert.equal(await reaches(publicPort), true);
			assert.deepEqual(hits, { local: 1, peer: 1 });
		} finally {
			local.close();
			remote.close();
		}
	});
});
