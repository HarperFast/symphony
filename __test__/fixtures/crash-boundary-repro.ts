/**
 * Standalone repro spawned as a real child process by suspended.spec.ts's "crash-boundary"
 * test — must run out-of-process because it deliberately triggers a throwing `'error'`
 * listener via a real resolveConnection() validation failure delivered through the napi
 * threadsafe-function callback (not a direct, in-process `proxy.emit('error', ...)` call,
 * which never exercises that boundary at all).
 *
 * Success criterion: stdout contains "CAUGHT:" (uncaughtException fired and was handled)
 * and the process exits 0 — a throw reached through the real native callback still surfaces
 * as an ordinary, catchable JS exception rather than hanging or killing the process by signal.
 */
import { SymphonyProxy } from '../../ts/proxy.js';
import { generateSelfSignedCert, getFreePort, sleep } from '../util.js';
import * as tls from 'node:tls';

async function main() {
	process.on('uncaughtException', (err) => {
		console.log(`CAUGHT: ${err.message}`);
		process.exit(0);
	});

	const cert = generateSelfSignedCert('localhost');
	const proxyPort = await getFreePort();
	const proxy = new SymphonyProxy({
		listeners: [{ host: '127.0.0.1', port: proxyPort }],
		routes: [
			{
				sni: 'localhost',
				upstreams: [],
				terminateTls: true,
				cert: { certChain: cert.cert, privateKey: cert.key },
				suspended: true,
				suspendTimeoutMs: 5000,
			},
		],
	});

	// A deliberately buggy consumer 'error' handler — this is exactly the scenario the
	// review flagged: if this throws inside the tsfn callback rather than on a deferred
	// tick, it crashes uncatchably instead of surfacing here.
	proxy.on('error', () => {
		throw new Error('deliberately buggy error listener');
	});

	proxy.on('suspended', (conn) => {
		// Undeclared xForwardedFor — rejected by parse_resolve_spec, emits 'error'.
		proxy.resolveConnection(conn.id, {
			upstream: { kind: 'tcp', host: '127.0.0.1', port: 1 },
			terminateTls: true,
			sourceAddressHeader: 'xForwardedFor',
		});
	});

	await proxy.start();
	await sleep(50);

	const socket = tls.connect({ port: proxyPort, host: '127.0.0.1', servername: 'localhost', ca: cert.cert, rejectUnauthorized: false });
	socket.on('error', () => {});

	// If nothing crashed and nothing was caught within this window, the fix (or the
	// deliberately-throwing listener) didn't do what this repro expects — fail loudly
	// rather than let the test hang.
	await sleep(2000);
	console.log('NEVER_THREW');
	process.exit(1);
}

main();
