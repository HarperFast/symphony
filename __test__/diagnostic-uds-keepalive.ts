/**
 * Diagnostic: Does Harper keep UDS connections alive between requests?
 *
 * Tests three scenarios:
 *   A) Direct UDS, no PROXY header, HTTP/1.1 keep-alive
 *   B) Direct UDS, with PROXY v1 header (like Symphony sends), HTTP/1.1 keep-alive
 *   C) Direct UDS, HTTP/1.0 (no keep-alive)
 *
 * Run with:
 *   npm run build:debug
 *   node dist-test/__test__/diagnostic-uds-keepalive.js
 */

import { createConnection, Socket } from 'node:net';
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { parse } from 'yaml';
import { createHarperContext, startHarper, teardownHarper } from '@harperfast/integration-testing';

function resolveHarperBin(): string {
	const siblingBuild = join(__dirname, '..', '..', '..', 'harper-pro', 'dist', 'bin', 'harper.js');
	if (existsSync(siblingBuild)) return siblingBuild;
	try {
		return join(require.resolve('harper'), '..', 'bin', 'harper.js');
	} catch {
		throw new Error('Harper CLI not found.');
	}
}

interface ParsedResponse {
	status: number;
	httpVersion: string;
	connection: string;   // value of Connection header, or '' if absent
	contentLength: number | null;
	chunked: boolean;
	body: Buffer;
	raw: string;          // raw header block for debugging
}

/**
 * Read exactly one HTTP/1.x response from `buf + incoming socket data`.
 * Resolves with the parsed response and any unconsumed bytes.
 */
function readOneResponse(socket: Socket, initialBuf: Buffer): Promise<{ response: ParsedResponse; leftover: Buffer }> {
	return new Promise((resolve, reject) => {
		let buf = initialBuf;

		// Try to parse whatever is already in buf, and keep reading until done.
		function tryParse() {
			// 1. Find end of headers.
			const sep = buf.indexOf('\r\n\r\n');
			if (sep === -1) return; // need more data

			const headerBlock = buf.slice(0, sep).toString('latin1');
			const bodyStart = sep + 4;
			buf = buf.slice(bodyStart);

			// 2. Parse status line.
			const firstLine = headerBlock.split('\r\n')[0];
			const m = firstLine.match(/^HTTP\/(\d+\.\d+)\s+(\d+)/);
			const httpVersion = m ? m[1] : '?';
			const status = m ? parseInt(m[2], 10) : 0;

			// 3. Parse headers we care about.
			const headers = headerBlock.toLowerCase();
			const connMatch = headers.match(/\nconnection:\s*([^\r\n]+)/);
			const connection = connMatch ? connMatch[1].trim() : '';

			const clMatch = headers.match(/\ncontent-length:\s*(\d+)/);
			const contentLength = clMatch ? parseInt(clMatch[1], 10) : null;

			const chunked = /\ntransfer-encoding:\s*chunked/.test(headers);

			// 4. Read body.
			if (contentLength !== null) {
				// Content-Length framing.
				readExact(contentLength, (body, leftover) => {
					resolve({ response: { status, httpVersion, connection, contentLength, chunked, body, raw: headerBlock }, leftover });
				});
			} else if (chunked) {
				// Chunked framing: read until terminal chunk.
				readChunked((body, leftover) => {
					resolve({ response: { status, httpVersion, connection, contentLength: null, chunked, body, raw: headerBlock }, leftover });
				});
			} else {
				// No body length indicator — assume no body (e.g. 204, HEAD).
				resolve({ response: { status, httpVersion, connection, contentLength: null, chunked: false, body: Buffer.alloc(0), raw: headerBlock }, leftover: buf });
				cleanup();
			}
		}

		function readExact(n: number, cb: (body: Buffer, leftover: Buffer) => void) {
			function check() {
				if (buf.length >= n) {
					const body = buf.slice(0, n);
					const leftover = buf.slice(n);
					cleanup();
					cb(body, leftover);
				}
			}
			check();
			if (buf.length < n) {
				socket.on('data', onData);
			}
			function onData(chunk: Buffer) {
				buf = Buffer.concat([buf, chunk]);
				if (buf.length >= n) {
					socket.off('data', onData);
					socket.off('close', onClose);
					socket.off('error', onError);
					const body = buf.slice(0, n);
					const leftover = buf.slice(n);
					cb(body, leftover);
				}
			}
			function onClose() { reject(new Error('socket closed while reading body')); }
			function onError(e: Error) { reject(e); }
			if (buf.length < n) {
				socket.on('close', onClose);
				socket.on('error', onError);
			}
		}

		function readChunked(cb: (body: Buffer, leftover: Buffer) => void) {
			const chunks: Buffer<ArrayBuffer>[] = [];
			function tryChunk() {
				// Each chunk: SIZE\r\n DATA\r\n ... terminal: 0\r\n\r\n
				while (true) {
					const crlf = buf.indexOf('\r\n');
					if (crlf === -1) return; // need more data
					const sizeStr = buf.slice(0, crlf).toString('latin1').split(';')[0].trim();
					const size = parseInt(sizeStr, 16);
					if (isNaN(size)) { reject(new Error(`bad chunk size: ${sizeStr}`)); return; }
					const dataStart = crlf + 2;
					if (size === 0) {
						// terminal chunk — skip trailing \r\n
						buf = buf.slice(dataStart + 2);
						cleanup();
						cb(Buffer.concat(chunks), buf);
						return;
					}
					if (buf.length < dataStart + size + 2) return; // need more data
					chunks.push(buf.slice(dataStart, dataStart + size));
					buf = buf.slice(dataStart + size + 2);
				}
			}
			tryChunk();
			if (chunks.length === 0 || buf.indexOf('0\r\n') !== -1) {
				socket.on('data', onData);
				socket.on('close', onClose);
				socket.on('error', onError);
			}
			function onData(chunk: Buffer) {
				buf = Buffer.concat([buf, chunk]);
				tryChunk();
			}
			function onClose() { reject(new Error('socket closed while reading chunked body')); }
			function onError(e: Error) { reject(e); }
		}

		function cleanup() {
			socket.off('data', onData2);
			socket.off('close', onClose2);
			socket.off('error', onError2);
		}

		// Initial parse attempt using data already in buf.
		const onData2 = (chunk: Buffer) => { buf = Buffer.concat([buf, chunk]); tryParse(); };
		const onClose2 = () => reject(new Error('socket closed before headers complete'));
		const onError2 = (e: Error) => reject(e);

		if (buf.indexOf('\r\n\r\n') !== -1) {
			tryParse();
		} else {
			socket.on('data', onData2);
			socket.on('close', onClose2);
			socket.on('error', onError2);
		}
	});
}

interface ScenarioResult {
	name: string;
	requestsSent: number;
	requestsAnswered: number;
	connectionHeaders: string[];   // Connection header from each response
	socketClosedAfter: number;     // which request caused the socket to close (0 = still open)
	error?: string;
}

async function runScenario(
	name: string,
	sockPath: string,
	hostname: string,
	numRequests: number,
	proxyHeader: string | null,
	httpVersion: '1.0' | '1.1',
): Promise<ScenarioResult> {
	const result: ScenarioResult = {
		name,
		requestsSent: 0,
		requestsAnswered: 0,
		connectionHeaders: [],
		socketClosedAfter: 0,
	};

	return new Promise((resolve) => {
		const socket = createConnection(sockPath);
		let closed = false;
		// eslint-disable-next-line @typescript-eslint/no-explicit-any
		let leftover: any = Buffer.alloc(0);

		socket.on('error', (err) => {
			result.error = err.message;
			resolve(result);
		});

		socket.on('close', () => {
			closed = true;
			if (result.socketClosedAfter === 0) {
				result.socketClosedAfter = result.requestsAnswered;
			}
			resolve(result);
		});

		socket.on('connect', async () => {
			// Send PROXY header once, before any HTTP request.
			if (proxyHeader) {
				socket.write(proxyHeader);
			}

			for (let i = 0; i < numRequests; i++) {
				if (closed) break;

				const connHeader = httpVersion === '1.1' ? 'Connection: keep-alive\r\n' : '';
				const req =
					`GET /benchmark HTTP/${httpVersion}\r\n` +
					`Host: ${hostname}\r\n` +
					connHeader +
					`\r\n`;

				socket.write(req);
				result.requestsSent++;

				try {
					const { response, leftover: lo } = await readOneResponse(socket, leftover);
					leftover = lo;
					result.requestsAnswered++;
					result.connectionHeaders.push(response.connection || '(absent)');

					// If server said Connection: close, stop.
					if (response.connection.toLowerCase() === 'close') {
						result.socketClosedAfter = result.requestsAnswered;
						break;
					}
				} catch (err: any) {
					result.error = err.message;
					break;
				}
			}

			if (!closed) {
				socket.destroy();
			}
			if (!closed) resolve(result);
		});
	});
}

function printResult(r: ScenarioResult) {
	console.log(`\n  Scenario: ${r.name}`);
	console.log(`    Requests sent:     ${r.requestsSent}`);
	console.log(`    Requests answered: ${r.requestsAnswered}`);
	console.log(`    Connection headers: ${r.connectionHeaders.join(', ') || '(none)'}`);
	if (r.socketClosedAfter > 0) {
		console.log(`    Socket closed after request #${r.socketClosedAfter}`);
	} else {
		console.log(`    Socket: remained open`);
	}
	if (r.error) {
		console.log(`    Error: ${r.error}`);
	}
}

async function main() {
	const harperBinPath = process.env.HARPER_INTEGRATION_TEST_INSTALL_SCRIPT
		? undefined
		: resolveHarperBin();

	console.log('Starting Harper...');
	const harperCtx = await startHarper(createHarperContext('symphony-diagnostic-keepalive'), {
		harperBinPath,
		config: {
			tls: { unixDomainSockets: true, tcp: true },
			threads: { count: 2 },
		},
	});

	const socketsDir = join(harperCtx.harper.dataRootDir, 'sockets');
	let yamlFiles: string[] = [];
	for (let attempt = 0; attempt < 60; attempt++) {
		try {
			yamlFiles = readdirSync(socketsDir).filter((f) => f.endsWith('.yaml'));
			if (yamlFiles.length > 0) break;
		} catch {}
		await new Promise((r) => setTimeout(r, 500));
	}
	if (yamlFiles.length === 0) throw new Error('No UDS metadata files found');

	const meta = parse(readFileSync(join(socketsDir, yamlFiles[0]), 'utf8'));
	const sockPath = join(socketsDir, yamlFiles[0].replace('.yaml', '.sock'));
	const cert = meta.certificates?.[0];
	const hostname = (cert?.hostnames as string[])?.find((h) => !/^[\d.:]+$/.test(h)) ?? 'localhost';

	console.log(`UDS socket: ${sockPath}`);
	console.log(`Hostname:   ${hostname}`);
	console.log(`\nSending 5 sequential requests per scenario on the SAME socket connection:`);

	const NUM = 5;
	const PROXY = `PROXY TCP4 127.0.0.1 127.0.0.1 12345 0\r\n`;

	const scenarios = [
		runScenario('HTTP/1.1, no PROXY header', sockPath, hostname, NUM, null, '1.1'),
		runScenario('HTTP/1.1, with PROXY header (like Symphony)', sockPath, hostname, NUM, PROXY, '1.1'),
		runScenario('HTTP/1.0 (no keep-alive)', sockPath, hostname, NUM, null, '1.0'),
	];

	const results = await Promise.all(scenarios.map((p) => p));
	for (const r of results) printResult(r);

	console.log('\n--- Interpretation ---');
	const [noProxy, withProxy] = results;
	if (noProxy.requestsAnswered === NUM) {
		console.log('✓ Harper keeps UDS connections alive for HTTP/1.1 without PROXY header.');
	} else {
		console.log(`✗ Harper closed the UDS connection after ${noProxy.requestsAnswered} request(s) without PROXY header.`);
	}
	if (withProxy.requestsAnswered === NUM) {
		console.log('✓ Harper keeps UDS connections alive for HTTP/1.1 WITH PROXY header.');
	} else {
		console.log(`✗ Harper closed the UDS connection after ${withProxy.requestsAnswered} request(s) WITH PROXY header.`);
	}

	await teardownHarper(harperCtx).catch(() => {});
	console.log('\nDone.');
}

main().catch((err) => {
	console.error('Diagnostic failed:', err);
	process.exit(1);
});
