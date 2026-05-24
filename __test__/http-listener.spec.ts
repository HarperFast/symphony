/**
 * Tests for the HTTP-mode listener (mode: 'http').
 *
 * Verifies:
 *   1. Non-ACME requests get a 301 redirect to https://<host><uri>.
 *   2. Requests to /.well-known/acme-challenge/* are proxied to the route
 *      matched by the Host header.
 *   3. ACME requests with no matching route get a 404.
 *
 * Requires the native addon to be built:
 *   npm run build:debug
 */

import assert from 'node:assert/strict';
import * as net from 'node:net';
import { after, before, describe, it } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import { getFreePort, sleep } from './util.js';

interface HttpEchoServer {
	port: number;
	requests: Buffer[];
	close(): Promise<void>;
}

/**
 * Start a tiny HTTP server that records every request and responds with the
 * given body. Used as the ACME-challenge upstream in tests.
 */
function startHttpEchoServer(body: string): Promise<HttpEchoServer> {
	return new Promise((resolve, reject) => {
		const requests: Buffer[] = [];
		const server = net.createServer((socket) => {
			const chunks: Buffer[] = [];
			socket.on('data', (chunk: Buffer) => {
				chunks.push(chunk);
				const buf = Buffer.concat(chunks);
				if (buf.includes('\r\n\r\n')) {
					requests.push(buf);
					socket.write(
						`HTTP/1.1 200 OK\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
					);
					socket.end();
				}
			});
			socket.on('error', () => {
				// Client closed early — ignore.
			});
		});
		server.listen(0, '127.0.0.1', () => {
			const { port } = server.address() as net.AddressInfo;
			resolve({
				port,
				requests,
				close: () => new Promise((res, rej) => server.close((e) => (e ? rej(e) : res()))),
			});
		});
		server.on('error', reject);
	});
}

/** Send a raw HTTP request and collect the full response (until the server closes the socket). */
function rawHttp(port: number, request: string): Promise<string> {
	return new Promise((resolve, reject) => {
		const sock = net.createConnection({ port, host: '127.0.0.1' }, () => {
			sock.write(request);
		});
		const chunks: Buffer[] = [];
		sock.on('data', (c: Buffer) => chunks.push(c));
		sock.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
		sock.on('error', reject);
		setTimeout(() => reject(new Error('rawHttp timeout')), 5000);
	});
}

describe('HTTP-mode listener', () => {
	let proxyPort: number;
	let echo: HttpEchoServer;
	let proxy: SymphonyProxy;

	before(async () => {
		proxyPort = await getFreePort();
		echo = await startHttpEchoServer('challenge-token-abc');

		proxy = new SymphonyProxy({
			listeners: [{ host: '127.0.0.1', port: proxyPort, mode: 'http' }],
			routes: [
				{
					sni: 'example.com',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: false,
				},
				{
					sni: '*.wild.example.com',
					upstreams: [{ kind: 'tcp', host: '127.0.0.1', port: echo.port }],
					terminateTls: false,
				},
			],
		});
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await echo.close();
	});

	it('redirects non-ACME requests to https://', async () => {
		const response = await rawHttp(
			proxyPort,
			'GET /some/page?x=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n',
		);
		assert.match(response, /^HTTP\/1\.1 301 Moved Permanently\r\n/);
		assert.match(response, /\r\nLocation: https:\/\/example\.com\/some\/page\?x=1\r\n/);
		assert.match(response, /\r\nContent-Length: 0\r\n/);
	});

	it('strips :port from Host header in redirect target', async () => {
		const response = await rawHttp(
			proxyPort,
			'GET / HTTP/1.1\r\nHost: example.com:80\r\nConnection: close\r\n\r\n',
		);
		assert.match(response, /\r\nLocation: https:\/\/example\.com\/\r\n/);
	});

	it('redirects unknown hosts (no route required for redirect)', async () => {
		const response = await rawHttp(
			proxyPort,
			'GET / HTTP/1.1\r\nHost: stranger.example.net\r\nConnection: close\r\n\r\n',
		);
		assert.match(response, /^HTTP\/1\.1 301 Moved Permanently\r\n/);
		assert.match(response, /\r\nLocation: https:\/\/stranger\.example\.net\/\r\n/);
	});

	it('proxies ACME challenge requests to the matched route upstream', async () => {
		const before = echo.requests.length;
		const response = await rawHttp(
			proxyPort,
			'GET /.well-known/acme-challenge/abc123 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n',
		);
		assert.match(response, /^HTTP\/1\.1 200 OK\r\n/);
		assert.match(response, /challenge-token-abc$/);

		const captured = echo.requests[before];
		assert.ok(captured, 'upstream received the proxied request');
		const captured_text = captured.toString('utf8');
		assert.match(captured_text, /^GET \/\.well-known\/acme-challenge\/abc123 HTTP\/1\.1\r\n/);
		assert.match(captured_text, /\r\nHost: example\.com\r\n/);
	});

	it('proxies ACME requests for wildcard-matched hosts', async () => {
		const before = echo.requests.length;
		const response = await rawHttp(
			proxyPort,
			'GET /.well-known/acme-challenge/wild HTTP/1.1\r\nHost: foo.wild.example.com\r\nConnection: close\r\n\r\n',
		);
		assert.match(response, /^HTTP\/1\.1 200 OK\r\n/);
		assert.ok(echo.requests.length > before, 'upstream got the wildcard ACME request');
	});

	it('returns 404 for ACME requests with no matching route', async () => {
		const response = await rawHttp(
			proxyPort,
			'GET /.well-known/acme-challenge/x HTTP/1.1\r\nHost: nowhere.example.net\r\nConnection: close\r\n\r\n',
		);
		assert.match(response, /^HTTP\/1\.1 404 Not Found\r\n/);
	});

	it('returns 400 for ACME requests missing a Host header', async () => {
		const response = await rawHttp(
			proxyPort,
			'GET /.well-known/acme-challenge/x HTTP/1.1\r\nConnection: close\r\n\r\n',
		);
		assert.match(response, /^HTTP\/1\.1 400 Bad Request\r\n/);
	});

	it('forces Connection: close on the upstream request (no keep-alive tunneling)', async () => {
		const before = echo.requests.length;
		await rawHttp(
			proxyPort,
			// Client requests keep-alive — the proxy must rewrite to close so a
			// follow-up pipelined non-ACME request can't reach the upstream.
			'GET /.well-known/acme-challenge/abc HTTP/1.1\r\nHost: example.com\r\nConnection: keep-alive\r\n\r\n',
		);
		const captured = echo.requests[before].toString('utf8');
		assert.match(captured, /\r\nConnection: close\r\n/);
		assert.doesNotMatch(captured, /\r\nConnection: keep-alive\r\n/i);
	});

	it('does not forward pipelined bytes that arrived past the header boundary', async () => {
		const before = echo.requests.length;
		// Send TWO requests on one socket: ACME first, then a non-ACME GET that
		// would otherwise expose the upstream over plain HTTP. The proxy must
		// close after the first response — the second request must NOT reach the
		// upstream, regardless of whether it arrives in the same syscall as the
		// first.
		const payload =
			'GET /.well-known/acme-challenge/abc HTTP/1.1\r\nHost: example.com\r\n\r\n' +
			'GET /admin HTTP/1.1\r\nHost: example.com\r\n\r\n';
		await rawHttp(proxyPort, payload);
		const newRequests = echo.requests.slice(before);
		assert.equal(newRequests.length, 1, 'upstream must see exactly one request');
		const text = newRequests[0].toString('utf8');
		assert.match(text, /^GET \/\.well-known\/acme-challenge\/abc /);
		assert.doesNotMatch(text, /\/admin/);
	});

	it('strips Content-Length and Transfer-Encoding when forwarding the ACME request', async () => {
		const before = echo.requests.length;
		await rawHttp(
			proxyPort,
			// A malicious client could lie about a body to deadlock the upstream.
			// The proxy must strip these headers since ACME challenges are bodyless GETs.
			'GET /.well-known/acme-challenge/abc HTTP/1.1\r\nHost: example.com\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n',
		);
		const captured = echo.requests[before].toString('utf8');
		assert.doesNotMatch(captured, /content-length/i);
		assert.doesNotMatch(captured, /transfer-encoding/i);
	});

	it('rejects a Host header containing CR/LF (response splitting guard)', async () => {
		// `Host: example.com\rEvil-Header: x` — without sanitization, `\r` ends
		// up in the Location header of the redirect and splits the response.
		const response = await rawHttp(
			proxyPort,
			'GET / HTTP/1.1\r\nHost: example.com\rEvil: x\r\nConnection: close\r\n\r\n',
		);
		assert.match(response, /^HTTP\/1\.1 400 Bad Request\r\n/);
		assert.doesNotMatch(response, /\r\nEvil:/);
	});
});
