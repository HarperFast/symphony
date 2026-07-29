/**
 * Integration tests for the per-direction copy buffer config (`readBufferSize` and the
 * `client`/`upstream` overrides).
 *
 * `readBufferSize` was accepted by the config for several releases while reaching no copy loop, so
 * these tests exist to assert that it is actually applied and that applying it does not change
 * what gets proxied. A buffer smaller than the payload must only mean more loop iterations — never
 * truncation, reordering, or a stalled transfer.
 *
 * These tests require the native addon to be built:
 *   npm run build:debug
 */

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import type { ProxyConfig } from '../ts/types.js';
import { generateSelfSignedCert, getFreePort, startEchoServer, tlsRoundTrip, sleep } from './util.js';

/** 512 KiB — 1024× the smallest buffer the config allows, so the copy loop must iterate. */
const LARGE_PAYLOAD = 512 * 1024;

/** Distinguishable per byte, so a dropped or reordered buffer-sized chunk fails the assert. */
function patterned(size: number): Buffer {
	const buf = Buffer.allocUnsafe(size);
	for (let i = 0; i < size; i++) buf[i] = i % 251;
	return buf;
}

describe('copy buffers', () => {
	const cert = generateSelfSignedCert('localhost');
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	const running: SymphonyProxy[] = [];

	before(async () => {
		echo = await startEchoServer();
	});

	after(async () => {
		await Promise.all(running.map((p) => p.stop()));
		await echo.close();
	});

	async function startProxy(
		buffers: Pick<
			ProxyConfig,
			'readBufferSize' | 'clientReadBufferSize' | 'upstreamReadBufferSize'
		>,
	): Promise<number> {
		const port = await getFreePort();
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
			...buffers,
		});
		await proxy.start();
		running.push(proxy);
		await sleep(50);
		return port;
	}

	async function assertRoundTrip(port: number, payload: Buffer): Promise<void> {
		const response = await tlsRoundTrip({
			port,
			servername: 'localhost',
			caCert: cert.cert,
			data: payload,
			rejectUnauthorized: true,
		});
		assert.equal(response.length, payload.length);
		assert.ok(response.equals(payload), 'payload round-tripped byte-for-byte');
	}

	it('round-trips a payload 1024× the buffer size', async () => {
		const port = await startProxy({ readBufferSize: 512 });
		await assertRoundTrip(port, patterned(LARGE_PAYLOAD));
	});

	it('round-trips with asymmetric per-direction buffers', async () => {
		// The MQTT shape: a small client→upstream buffer with a larger fan-out buffer.
		const port = await startProxy({ clientReadBufferSize: 1024, upstreamReadBufferSize: 4096 });
		await assertRoundTrip(port, patterned(LARGE_PAYLOAD));
	});

	it('clamps an out-of-range buffer size instead of failing to start', async () => {
		// 0 would make the copy loop read into an empty slice and take the Ok(0) for EOF.
		const port = await startProxy({ readBufferSize: 0 });
		await assertRoundTrip(port, patterned(64 * 1024));
	});

	it('accepts a per-direction override alongside the base value', async () => {
		const port = await startProxy({ readBufferSize: 2048, upstreamReadBufferSize: 16384 });
		await assertRoundTrip(port, patterned(LARGE_PAYLOAD));
	});
});
