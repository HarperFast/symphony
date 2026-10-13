/**
 * The memory benchmark's environment hooks (`src/bench_hooks.rs`, driven by
 * `bench-copy-memory-oop.ts`): read at construction, rejected loudly when malformed, and harmless
 * to what gets proxied when set.
 *
 * These tests require the native addon to be built:
 *   npm run build:debug
 */

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import { generateSelfSignedCert, getFreePort, sleep, startEchoServer, tlsRoundTrip } from './util.js';

const TLS_BUFFER_LIMIT = 'SYMPHONY_TLS_BUFFER_LIMIT';
const MALLOC_TRIM = 'SYMPHONY_MALLOC_TRIM_INTERVAL_MS';
const hasGlibc = Boolean(
	(process.report.getReport() as { header: { glibcVersionRuntime?: string } }).header.glibcVersionRuntime
);

/** Distinguishable per byte, so a dropped or reordered chunk fails the assert. */
function patterned(size: number): Buffer {
	const buf = Buffer.allocUnsafe(size);
	for (let i = 0; i < size; i++) buf[i] = i % 251;
	return buf;
}

describe('memory benchmark hooks', () => {
	const cert = generateSelfSignedCert('localhost');
	let echo: Awaited<ReturnType<typeof startEchoServer>>;

	before(async () => {
		echo = await startEchoServer();
	});

	after(async () => {
		await echo.close();
	});

	/** The hooks are read in the constructor, so the variables only need to exist around it. */
	async function proxyWith(env: Record<string, string>): Promise<{ proxy: SymphonyProxy; port: number }> {
		const port = await getFreePort();
		Object.assign(process.env, env);
		try {
			const proxy = new SymphonyProxy({
				listeners: [{ host: '127.0.0.1', port }],
				routes: [
					{
						sni: 'localhost',
						upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
						terminateTls: true,
						cert: { certChain: cert.cert, privateKey: cert.key },
					},
				],
			});
			return { proxy, port };
		} finally {
			for (const name of Object.keys(env)) delete process.env[name];
		}
	}

	it('rejects a malformed or too-small value instead of running without it', async () => {
		for (const [name, value] of [
			[TLS_BUFFER_LIMIT, '0'],
			[TLS_BUFFER_LIMIT, '16k'],
			[MALLOC_TRIM, '0'],
			[MALLOC_TRIM, 'soon'],
		]) {
			await assert.rejects(proxyWith({ [name]: value }), new RegExp(name), `${name}=${value}`);
		}
	});

	it('a TLS buffer limit far below the payload still delivers every byte in order', async () => {
		const { proxy, port } = await proxyWith({ [TLS_BUFFER_LIMIT]: '1024' });
		await proxy.start();
		try {
			const payload = patterned(512 * 1024);
			const echoed = await tlsRoundTrip({ port, servername: 'localhost', data: payload });
			assert.ok(echoed.equals(payload), `echoed ${echoed.length} of ${payload.length} bytes, or out of order`);
		} finally {
			await proxy.stop();
		}
	});

	it(
		'the trim loop runs alongside traffic and ends with each proxy',
		{ skip: !hasGlibc && 'malloc_trim is glibc-only' },
		async () => {
			for (let i = 0; i < 2; i++) {
				const { proxy, port } = await proxyWith({ [MALLOC_TRIM]: '100' });
				await proxy.start();
				try {
					await sleep(350);
					const echoed = await tlsRoundTrip({ port, servername: 'localhost', data: 'trimmed' });
					assert.equal(echoed.toString(), 'trimmed');
				} finally {
					await proxy.stop();
				}
			}
		}
	);
});
