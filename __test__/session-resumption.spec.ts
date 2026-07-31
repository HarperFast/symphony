/**
 * TLS session resumption — that symphony offers it at all, and that a config reload doesn't
 * silently take it away.
 *
 * The second property is the fragile one. Resumption state (the TLS 1.2 session cache and the
 * TLS 1.3 ticket keys) lives on the rustls `ServerConfig`, so anything that rebuilds a config
 * for an unchanged cert invalidates every ticket already handed out — with no error anywhere,
 * just a quiet return to full handshakes. Reloads are routine in production (a route add or an
 * on-disk cert renewal rebuilds the whole route table), so without a route-table-outliving
 * config cache, clients would rarely get to resume at all.
 *
 * Requires the native addon:
 *   npm run build:debug
 */

import assert from 'node:assert/strict';
import { after, before, describe, it } from 'node:test';
import { SymphonyProxy } from '../ts/proxy.js';
import { generateSelfSignedCert, getFreePort, startEchoServer, tlsHandshake, sleep } from './util.js';

describe('TLS session resumption', () => {
	const cert = generateSelfSignedCert('localhost');
	let proxyPort: number;
	let echo: Awaited<ReturnType<typeof startEchoServer>>;
	let proxy: SymphonyProxy;

	const routes = () => [
		{
			sni: 'localhost',
			upstreams: [{ kind: 'tcp' as const, host: '127.0.0.1', port: echo.port }],
			terminateTls: true,
			cert: { certChain: cert.cert, privateKey: cert.key },
		},
	];

	before(async () => {
		echo = await startEchoServer();
		proxyPort = await getFreePort();
		proxy = new SymphonyProxy({ listeners: [{ host: '127.0.0.1', port: proxyPort }], routes: routes() });
		await proxy.start();
		await sleep(50);
	});

	after(async () => {
		await proxy.stop();
		await echo.close();
	});

	for (const maxVersion of ['TLSv1.3', 'TLSv1.2'] as const) {
		describe(maxVersion, () => {
			it('issues a session and resumes it on a second connection', async () => {
				const first = await tlsHandshake({ port: proxyPort, servername: 'localhost', caCert: cert.cert, maxVersion });
				assert.equal(first.protocol, maxVersion);
				assert.equal(first.reused, false, 'the first handshake cannot be a resumption');
				assert.ok(first.session, 'the server must issue a session to resume against');

				const second = await tlsHandshake({
					port: proxyPort,
					servername: 'localhost',
					caCert: cert.cert,
					maxVersion,
					session: first.session,
				});
				assert.equal(second.reused, true, 'the offered session must be accepted');
			});

			// The regression this file exists for: a reload that leaves the cert untouched must
			// leave outstanding sessions resumable. It reproduces as reused === false.
			it('keeps sessions resumable across an updateConfig() that does not change the cert', async () => {
				const first = await tlsHandshake({ port: proxyPort, servername: 'localhost', caCert: cert.cert, maxVersion });
				assert.ok(first.session);

				await proxy.updateConfig({ routes: routes() });
				await sleep(50);

				const afterReload = await tlsHandshake({
					port: proxyPort,
					servername: 'localhost',
					caCert: cert.cert,
					maxVersion,
					session: first.session,
				});
				assert.equal(
					afterReload.reused,
					true,
					'a reload must not mint a new ServerConfig for an unchanged cert — that discards the ticket keys'
				);
			});
		});
	}

	// A rotated cert is a different identity: its predecessor's session state going away is
	// correct, not a regression. Asserted so the sweep isn't "fixed" into retaining forever.
	it('does not resume a session across a cert rotation', async () => {
		const first = await tlsHandshake({
			port: proxyPort,
			servername: 'localhost',
			caCert: cert.cert,
			maxVersion: 'TLSv1.3',
		});
		assert.ok(first.session);

		const rotated = generateSelfSignedCert('localhost');
		await proxy.updateConfig({
			routes: [{ ...routes()[0], cert: { certChain: rotated.cert, privateKey: rotated.key } }],
		});
		await sleep(50);

		const afterRotation = await tlsHandshake({
			port: proxyPort,
			servername: 'localhost',
			caCert: rotated.cert,
			maxVersion: 'TLSv1.3',
			session: first.session,
		});
		assert.equal(afterRotation.reused, false, 'a session issued under the old cert must not resume under the new one');

		// Restore the original cert so ordering between tests stays irrelevant.
		await proxy.updateConfig({ routes: routes() });
		await sleep(50);
	});
});
