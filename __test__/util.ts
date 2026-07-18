import * as crypto from 'node:crypto';
import * as net from 'node:net';
import * as tls from 'node:tls';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

// ── Self-signed certificate generation ────────────────────────────────────────

export interface SelfSignedCert {
	cert: string; // PEM certificate chain
	key: string; // PEM private key
}

/**
 * Generate a self-signed RSA certificate for testing.
 * Uses Node's built-in crypto — no external tool required.
 */
export function generateSelfSignedCert(hostname = 'localhost'): SelfSignedCert {
	const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

	const cert = (crypto as any).X509Certificate
		? generateCertViaOpenssl(hostname, privateKey, publicKey)
		: generateCertFallback();

	return cert;
}

function generateCertFallback(): SelfSignedCert {
	// Use pre-baked test certs (generated offline) when the Node crypto API
	// does not expose X509Certificate generation.
	// These are self-signed certs valid for localhost, for testing only.
	const key = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLF29amygykEMmYz0+Kcj3bKBp29T1MLUj9OTKZH
XzSQuIGGbzl6bz/d5vxLB1QAZB4fGFmLGQRfP5jUzQENPEJU7nRiAkHOLbqPBpOE
vHRkdMjHK0GMsWfqWRNyQOQ7mCB9STMoNAFBzHETJLfHcNuaAH5r93wXxkHoekKP
sZ6WGCDy65eNFoLBiNvxuMQwRHtOBqlIHMbhJf/YFfQJQZ0jmXBVoFE8M+VAFXAF
QKxCzaA/mQ7MiGFt1mKgTKRbHNLHIaI1fxblBCo4NsJyzmZfmjrSf2xYPmFm2k0e
YnL5yL72SBp5lRByUivJGWCqYIBm0a7S9l5z1QIDAQABAoIBAHHigFgGFQ8FV3aI
rDRGDSKBMRaZFv7dUfGlVXNt3fYOMNr8xIFzVpRmpzVWoiCWLCPlm6pxfcxb3bkT
f7geDMGqAIFMOKzFbBDg5xXjx0MnFhGfvICe4JiLThfLCXFN78l9sKxJxVsMO0kP
1yJuQ6hAl4eFRHaBbK6OFN7s1L1NVqOJVVPIRaGbDnPhEQqIWkIaKBpYTBiRXsxq
1i3TBkMRzXaJ9e4KpP0/MeH5vBHfXLqJkPDL1gkm0GNg5CJFBjJLfJqY5nB3JHfI
b35zWYoBcYgT1UzpT+zz1UGJ/vlRZOQ3Q5LE9vHxbmznROCLRNkZE5o8a3RQXYTQ
BcUxqQECgYEA7kHLhPcTCT/j3h/0MFdPnktCwO9RJK7D2dUd5j0RSTJ7NKHYkJzj
i3HVGnVYTg8vT7Q1Qm7MJQQrpVkpQNGqO7WGbIBT5Gs0xm5iyRNrIlEGMNX2x4I3
1RpGSrpYVD9XRDJI4SLYWXeMxOuGfRYHaMfAkZZHEpGiXZ78Xy9B6YkCgYEA6TXB
B6XD4VzNsNELzuAzQyYnOziFHM3Oo7Y8ORN8bxNFHGYDdQPBxaMo2RVxBgObbCF0
O6/YFnXDGR3OaHkz9V2NLQHQYZ1CZvTp+q+rXP5X4o5TNiYlVxnOFw3s7KDSmEIi
vHG2I6dYI1E5DqR9YgBqBjpPVPOmvf+Wqaq2M4ECgYEAiZrjCkzQ9GJcRoEGBORX
VCQgpEbHpFgJrONnzR8x3UqZpS8kCg6DHKM82eJBB4VPM7g3J7PD8W8i5iN3bvwE
GolPsMMLCVEqQdInPKWYTUb+EBsPRBwIJqT+F23b0yfJO3rGrG8Ae4gVBvAHQ56m
tPIpZeRz5GarADmT/VE5pukCgYA0U6mvCPUgdg5q3u6JQNP7oM1k3K+IJSQZQ3bJ
0H7eL+yjWcflMJHXAPlPlNi7TIa+kPJEbkCsB5jI2F4C7NQtaL2gkZR9RkRdRFG2
mS+/MFxUq0vNZJpInf8KFdGS+ZMJZ7xXMhLQUfCg6fhh7aTRuDhpUCiQ1SrmhsXE
ugSXAQKBgBqovz/bYHpqKCyE5E3n4yLMQX9b/DKbYOm0l6j3yCWdEZPNzx2mpGaz
aTUZq+xqnC3ikHAFZHC1o8TyIJAWcyq/aNs/+GkHvmqVFzXO5A9g7p0GiN1TQRJ7
B8pCXAC+5LXXxJkBCm1dCbGpkpkqJlpxn7QkuDV+JQ4mYRAKnIIf
-----END RSA PRIVATE KEY-----`;

	const cert = `-----BEGIN CERTIFICATE-----
MIICpDCCAYwCCQDU+pQ4pHgSpDANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAls
b2NhbGhvc3QwHhcNMjQwMTAxMDAwMDAwWhcNMjUwMTAxMDAwMDAwWjAUMRIwEAYD
VQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDZ
ravCmUFAsXb1qbKDKQQyZjPT4pyPdsoGnb1PUwtSP05MpkdfNJC4gYZvOXpvP93m
/EsHVABkHh8YWYsZBF8/mNTNAQ08QlTudGICQc4tuo8Gk4S8dGR0yMcrQYyxZ+pZ
E3JA5DuYIH1JMyg0AUHMcRMkt8dw25oAfmv3fBfGQeh6Qo+xnpYYIPLrl40WgsGI
2/G4xDBEe04GqUgcxuEl/9gV9AlBnSOZcFWgUTwz5UAVcAVArELNoD+ZDsyIYW3W
YqBMpFsc0schojV/FuUEKjg2wnLOZl+aOtJ/bFg+YWbaTR5icvnIvvZIGnmVEHJS
K8kZYKpggGbRrtL2XnPVAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAAfKiWXEfL47
gI7fmJvpqLO7BDUNL/Gfm/pXJJKvGCvHmzRuQIHzEE7HyDg/2Y8dBRLCFKsLR7
HLH0hY/9n4wUQCbq0pJhRLCGp+oIwv3JRPW7i4XCJCR6+4NkUl74MInkGj5eRhS
AuVJDHyp7hS5DXOlGPJEFUvGTjBJh5vlHm+AULH7dE1lU+bJxI+P5yHSILyXTTR
g0RPjVjJ/CqASEQBRF+NMz0gT+zQ6hWd+mY26m0aXGHhz0yyXPz6xfnJz0VHk5
9NeF+/RCUuXoJTEdFzCASSAlQeE9BkLdEjP7gI7Wx8Y4+gDRTM1K0gWQmhkMHhh
N1X9O4g0JDs=
-----END CERTIFICATE-----`;

	return { cert, key };
}

function generateCertViaOpenssl(
	hostname: string,
	privateKey: crypto.KeyObject,
	_publicKey: crypto.KeyObject,
): SelfSignedCert {
	// Node.js >= 15.6.0 supports generating X.509 certs via the `x509` module.
	// We use the spawnSync fallback via a temp directory to keep it simple and
	// compatible across Node 18/20/22.
	const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'symphony-test-'));
	const keyFile = path.join(dir, 'key.pem');
	const certFile = path.join(dir, 'cert.pem');

	const keyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
	fs.writeFileSync(keyFile, keyPem);

	const { spawnSync } = require('node:child_process');
	const result = spawnSync(
		'openssl',
		[
			'req',
			'-new',
			'-x509',
			'-key',
			keyFile,
			'-out',
			certFile,
			'-days',
			'1',
			'-subj',
			`/CN=${hostname}`,
			'-addext',
			`subjectAltName=DNS:${hostname},IP:127.0.0.1`,
		],
		{ encoding: 'utf8' },
	);

	if (result.status !== 0) {
		fs.rmSync(dir, { recursive: true });
		return generateCertFallback();
	}

	const cert = fs.readFileSync(certFile, 'utf8');
	fs.rmSync(dir, { recursive: true });

	// Export private key in traditional PKCS1 format for rustls compatibility
	const rsaResult = spawnSync(
		'openssl',
		['rsa', '-in', '/dev/stdin', '-out', '/dev/stdout'],
		{ input: keyPem, encoding: 'utf8' },
	);
	const key = rsaResult.status === 0 ? rsaResult.stdout : keyPem;

	return { cert, key };
}

// ── Free port helper ───────────────────────────────────────────────────────────

/** Obtain a free TCP port on localhost. */
export function getFreePort(): Promise<number> {
	return new Promise((resolve, reject) => {
		const server = net.createServer();
		server.listen(0, '127.0.0.1', () => {
			const { port } = server.address() as net.AddressInfo;
			server.close((err) => (err ? reject(err) : resolve(port)));
		});
	});
}

// ── Echo server helper ────────────────────────────────────────────────────────

export interface EchoServer {
	port: number;
	close(): Promise<void>;
}

/** Start a plain TCP echo server (for passthrough tests). */
export function startEchoServer(): Promise<EchoServer> {
	return new Promise((resolve, reject) => {
		const server = net.createServer((socket) => {
			socket.pipe(socket);
		});
		server.listen(0, '127.0.0.1', () => {
			const { port } = server.address() as net.AddressInfo;
			resolve({
				port,
				close: () =>
					new Promise((res, rej) => server.close((e) => (e ? rej(e) : res()))),
			});
		});
		server.on('error', reject);
	});
}

export interface CaptureServer {
	port: number;
	/** Resolves with all bytes received on the first connection (debounced 150ms after the last chunk). */
	received: Promise<Buffer>;
	close(): Promise<void>;
}

/**
 * Start a plain TCP server that captures the raw bytes an upstream would receive — used to
 * inspect the PROXY protocol header / injected HTTP headers symphony prepends. Does not echo.
 */
export function startCaptureServer(): Promise<CaptureServer> {
	return new Promise((resolve, reject) => {
		let resolveReceived!: (b: Buffer) => void;
		const received = new Promise<Buffer>((res) => {
			resolveReceived = res;
		});
		const chunks: Buffer[] = [];
		let timer: NodeJS.Timeout | undefined;
		const server = net.createServer((socket) => {
			socket.on('data', (c: Buffer) => {
				chunks.push(c);
				if (timer) clearTimeout(timer);
				timer = setTimeout(() => resolveReceived(Buffer.concat(chunks)), 150);
			});
		});
		server.listen(0, '127.0.0.1', () => {
			const { port } = server.address() as net.AddressInfo;
			resolve({
				port,
				received,
				close: () =>
					new Promise((res, rej) => server.close((e) => (e ? rej(e) : res()))),
			});
		});
		server.on('error', reject);
	});
}

/** Start a TLS echo server (for terminate-TLS tests). */
export function startTlsEchoServer(certPem: string, keyPem: string): Promise<EchoServer> {
	return new Promise((resolve, reject) => {
		const server = tls.createServer({ cert: certPem, key: keyPem }, (socket) => {
			socket.pipe(socket);
		});
		server.listen(0, '127.0.0.1', () => {
			const { port } = server.address() as net.AddressInfo;
			resolve({
				port,
				close: () =>
					new Promise((res, rej) => server.close((e) => (e ? rej(e) : res()))),
			});
		});
		server.on('error', reject);
	});
}

// ── TLS client helper ─────────────────────────────────────────────────────────

/** Send data through a TLS connection to the proxy and return the echoed response. */
export function tlsRoundTrip(opts: {
	port: number;
	host?: string;
	servername: string;
	caCert?: string;
	data: Buffer | string;
	rejectUnauthorized?: boolean;
}): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		const { port, host = '127.0.0.1', servername, caCert, data, rejectUnauthorized = false } = opts;
		const socket = tls.connect(
			{ port, host, servername, ca: caCert, rejectUnauthorized },
			() => {
				socket.write(data);
			},
		);
		const chunks: Buffer[] = [];
		socket.on('data', (chunk: Buffer) => {
			chunks.push(chunk);
			// Close after receiving at least as much as we sent
			const sent = Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data);
			if (Buffer.concat(chunks).length >= sent) {
				socket.end();
			}
		});
		socket.on('end', () => resolve(Buffer.concat(chunks)));
		socket.on('error', reject);
		setTimeout(() => reject(new Error('tlsRoundTrip timeout')), 5000);
	});
}

/**
 * Open a TLS connection offering the given ALPN protocols and return the
 * protocol the server negotiated (empty string if none). Used to verify that a
 * route's `http2` flag reaches the Rust side and drives ALPN advertisement.
 */
export function tlsAlpn(opts: {
	port: number;
	host?: string;
	servername: string;
	caCert?: string;
	alpnProtocols: string[];
	rejectUnauthorized?: boolean;
}): Promise<string> {
	return new Promise((resolve, reject) => {
		const { port, host = '127.0.0.1', servername, caCert, alpnProtocols, rejectUnauthorized = false } = opts;
		const socket = tls.connect(
			{ port, host, servername, ca: caCert, ALPNProtocols: alpnProtocols, rejectUnauthorized },
			() => {
				resolve(socket.alpnProtocol || '');
				socket.end();
			},
		);
		socket.on('error', reject);
		setTimeout(() => reject(new Error('tlsAlpn timeout')), 5000);
	});
}

/** Send data through a raw TCP connection and return the echoed response. */
export function tcpRoundTrip(opts: { port: number; host?: string; data: Buffer | string }): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		const { port, host = '127.0.0.1', data } = opts;
		const socket = net.createConnection({ port, host }, () => {
			socket.write(data);
		});
		const chunks: Buffer[] = [];
		socket.on('data', (chunk: Buffer) => {
			chunks.push(chunk);
			const sent = Buffer.isBuffer(data) ? data.length : Buffer.byteLength(data);
			if (Buffer.concat(chunks).length >= sent) {
				socket.end();
			}
		});
		socket.on('end', () => resolve(Buffer.concat(chunks)));
		socket.on('error', reject);
		setTimeout(() => reject(new Error('tcpRoundTrip timeout')), 5000);
	});
}

/** Sleep for `ms` milliseconds. */
export const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));
