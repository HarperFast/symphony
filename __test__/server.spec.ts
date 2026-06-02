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
