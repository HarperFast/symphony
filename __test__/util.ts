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

// ── CA-signed client certificates (for mTLS tests) ────────────────────────────

export interface ClientCa {
	caCert: string;
	clientCert: string;
	clientKey: string;
}

// Pre-baked test-only fixtures (100-year validity), generated once with OpenSSL 3.
// Static rather than openssl-at-runtime because rustls's webpki rejects the certs
// some `openssl` builds emit (macOS LibreSSL produces a CA cert webpki flags as
// ExtensionValueInvalid) — static PEMs keep the mTLS tests deterministic and
// platform-independent (no openssl dependency, no per-run key generation).
const CLIENT_CA: ClientCa = {
	caCert: `-----BEGIN CERTIFICATE-----
MIIDZTCCAk2gAwIBAgIUEF7vj9P1L6t/ReRJQeYzN82am8QwDQYJKoZIhvcNAQEL
BQAwOTEgMB4GA1UEAwwXU3ltcGhvbnkgVGVzdCBDbGllbnQgQ0ExFTATBgNVBAoM
DFN5bXBob255VGVzdDAgFw0yNjA3MTgxMzQyMTBaGA8yMTI2MDYyNDEzNDIxMFow
OTEgMB4GA1UEAwwXU3ltcGhvbnkgVGVzdCBDbGllbnQgQ0ExFTATBgNVBAoMDFN5
bXBob255VGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAN/YqoWm
lmt/CMjHjQ9WNL1LCJiZxSbDHScfdZ7xz2dnxcmgKvtnT89KpT/6NkKJTvTi1n3I
6fCIYex2iaoKYUfaH0QVA//dB1J6a4ChDcdx+ohTvAvlKqWwgKR3lJtY769JpXzI
e25cVEu2TbxGzPyWc6YtSKtraesYEpVJ+RONvzA2tJe2nVOOoQGNI1gV50oJVI21
dqWsX8KOFAO7GpHrXb5e47K3Qu1Dzbc0fEWZcUzkKfGjE4qcVMwnb+g41aDZsLBj
5Hp/KD7C42W9ee1w1DZJXfBIE+GmT/IZJSQJyWHewNL6KBVGy6wkb5RKExWdg84V
idLMZLAAPlkexDsCAwEAAaNjMGEwHQYDVR0OBBYEFFWMZI8FBTDQXio2v30dFKif
opwrMB8GA1UdIwQYMBaAFFWMZI8FBTDQXio2v30dFKifopwrMA8GA1UdEwEB/wQF
MAMBAf8wDgYDVR0PAQH/BAQDAgEGMA0GCSqGSIb3DQEBCwUAA4IBAQBv3QCvePct
QheCekCR1UaelVw7Dlxr9bTa32l3Jj1fT0A0ieIPEs5HhJjAwajgzsWJhxvpK9Nh
rzBjqrFFyUfa7gD8jq7eo+SbzRCqfaPb2AbfH3oJGEwjN882yBNlEo6YSUHKgoij
DGt00LDVckGw3FgRm+r2vOOfgRuViurg1vsrB3Qrp8S59LOP4HefT/gvZJG3LPCP
XKPFzo9SZbIfxifIR3T+f3VucNftjDexJOdEiUbipg7eaMbtoUOfC9ZtrZhZ6//9
I10pOHe5pCnHouQbfgdDl9UGf/69u7C9rR5OqTu2fEfMurDtJNdNVrlG584AmvCi
0HT7B9Ssuw8Z
-----END CERTIFICATE-----`,
	clientCert: `-----BEGIN CERTIFICATE-----
MIIDaDCCAlCgAwIBAgIUEFzv6k57sDnirppErxDK/BrhBZowDQYJKoZIhvcNAQEL
BQAwOTEgMB4GA1UEAwwXU3ltcGhvbnkgVGVzdCBDbGllbnQgQ0ExFTATBgNVBAoM
DFN5bXBob255VGVzdDAgFw0yNjA3MTgxMzQyMTFaGA8yMTI2MDYyNDEzNDIxMVow
LTEUMBIGA1UEAwwLdGVzdC1jbGllbnQxFTATBgNVBAoMDFN5bXBob255VGVzdDCC
ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK4dzF7JEgeW5lkBNSEXifLt
KVhYwhpM+9jd5i8nQn8mSLz5qNZywDUqbWiUFjCEaGdBxiFekDy/9uhUu5AKGAIu
C3YNVc591mg9vSvYcDbhmagVW5WDZtdifRKfaxp++AycImtFZze848bRABwYuEx2
rQAAuelOt4vca4M4Yh7HP5ZVzjPzTYwjWF7EReXgo3QBRJgeh3cIpN8H6bL+WTh5
dluuj4qdWf1bOJnLwknuRkAOxm+ad/NYOnUvcHOCKSfg/pKeRzTdtedb3GZr6Mj4
1iUI3uRzfQ9FksXdVa5JkR86zRa0LVJdr5b4HaXaJfiC8Om7YqQDxmhXFatJ96UC
AwEAAaNyMHAwCQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYI
KwYBBQUHAwIwHQYDVR0OBBYEFJW1XF3Q5gkI4FphVfKwXeNjizrUMB8GA1UdIwQY
MBaAFFWMZI8FBTDQXio2v30dFKifopwrMA0GCSqGSIb3DQEBCwUAA4IBAQA7nHbX
ntSqMqFx2RBMoRAPqxlRK0JTYIbFDK/vmM3J7Z9Yl+0DQVfQ58u4iJYpREj9b+AT
/QjEEoShhY370z89EqqQThhnFPAorHJ/rZ4rEMlahI69sVvTuYZ17Lyf4aeQ/rtZ
Bjk1zGeKX5GPpyO3eq615Od3flTd/ooDbzGIybj9bAFKAQ8rcnMi270lP42ub1Kn
iHe5wWGJaUP7OGP3AEZ0CvFjJfizKb3BdynU7cYCoENV0jGSeoS3TpedVDmT2Fmq
MW+TFySTK4D9Aa0UMjbQo4breSc/zP2io3saVG3NMhuzn41vqV3GFqElHb/Tn5zf
f7qyl7d3Q2jk3LN+
-----END CERTIFICATE-----`,
	clientKey: `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCuHcxeyRIHluZZ
ATUhF4ny7SlYWMIaTPvY3eYvJ0J/Jki8+ajWcsA1Km1olBYwhGhnQcYhXpA8v/bo
VLuQChgCLgt2DVXOfdZoPb0r2HA24ZmoFVuVg2bXYn0Sn2safvgMnCJrRWc3vOPG
0QAcGLhMdq0AALnpTreL3GuDOGIexz+WVc4z802MI1hexEXl4KN0AUSYHod3CKTf
B+my/lk4eXZbro+KnVn9WziZy8JJ7kZADsZvmnfzWDp1L3Bzgikn4P6Snkc03bXn
W9xma+jI+NYlCN7kc30PRZLF3VWuSZEfOs0WtC1SXa+W+B2l2iX4gvDpu2KkA8Zo
VxWrSfelAgMBAAECggEACFDtCMlCvrENjx+4eWb7PuqRPc0ozC0eyZoORfSdP58a
UfL8sO1p0mrp2dkE1va5WSvc5OLJhyqbW40R06HfyVmIpkVMcrXeQ+alqTlHtsn/
VvYE2fcc4NmtOUf69hjYC8YjULX6ZZZJ13OhCovVtZ/kyGoVzG0RkDEMGN2HC4rg
JTbS6u3krIOJJNYhIOUH8f4WTZip0WCJxiwZN+97J7H5tg1JOkST18Z5oeYJ0lFY
OxpISyaBGASQ3ri6ZDAuXPKK3FTceIzrVFvbfif4IRefo8wJPjeEagnrV/rkQ16+
ctx6keMhvFiZxAG1JMH1ZsRutke0ptDI4kQpDYg78QKBgQDklDF3B0J7yimVvbB5
cD7S3bx7XFVcjWNu4oxsKzslzO9B9sgxntxvVDtKfNnd5zBARS1f30v7aHYZcwJ7
NJ02PZD2qtCV93yJBSdb7v2maJVfdEOX9nA63/aWB43XOfyoEpwGdtzhG9XiBcKf
5XNB7q3rEUy0R3Ommjl1SbFMmQKBgQDDAQbYqPpnUopUSOQX/9lVHgdeaFj+QT+m
KgUItiw0gn9Azz9hYPQXWrw6eDBph4uj1DV05SlEoI6N1y0SST9whrTcJbXF19bR
pMF70TvGVMuY+nw2dOi454rZh5dEeYi5NdGD7RxzR9rfogSV0473R74/WZrBSwMA
fbQ7/QE+7QKBgEm5iqLLkqP+tp73ib4BeCHnJu3bACVT7ShMpeIVp4Qvr1PlVvi6
Nnsp/d2um065TJTOOy5bBVTXgo/+ymQWukZOYT1OJuzX4DEJmoJKeUF9JgCdrVeM
QvKaXhxR32v15goHxo9HM0LgCYJXPUj5Zs1zQGE7OTREf4bS44ly9V6xAoGBAKBX
t8lvKHbM5/Fl/ie9uHbEukpmgsaN4EhBROJk6PREWV5xCyyHDC4n7Z4mNaiQS8Hq
PApiZAyJ+K2owObIU+Gy4gQi/dQwJfM8BdxJr1zlXIPtczVT7AgeW42CcF9dj467
MgvIbBxeeRppnluUGXo7A7QTeax2gYFl2014PA4BAoGADyb+jfj8HuDN01xr6EkZ
Iz4zMqpDVBw5NA/N4VojDfOOX6dMRJVX6x3vWwSefcNVBS+t9ZfHAkx4JDd1z0Ce
oarboHnLg0PGnHE1GZCMaSwQXxZMohuyVEsZn1IqQPZeiabA05V8ZtPgYs5lxHrY
IKnIDfpBnIFOjhP/86KP7fU=
-----END PRIVATE KEY-----`,
};

// A second, independent CA + client, for the "cert signed by a different CA is rejected" test.
const OTHER_CLIENT_CA: ClientCa = {
	caCert: '', // not needed — the route trusts CLIENT_CA, and this client is signed by a different CA
	clientCert: `-----BEGIN CERTIFICATE-----
MIIDXzCCAkegAwIBAgIUciD6p9vUW/4ibbb3vjCfuLb4wKAwDQYJKoZIhvcNAQEL
BQAwLzEWMBQGA1UEAwwNT3RoZXIgVGVzdCBDQTEVMBMGA1UECgwMU3ltcGhvbnlU
ZXN0MCAXDTI2MDcxODEzNDI0M1oYDzIxMjYwNjI0MTM0MjQzWjAuMRUwEwYDVQQD
DAxvdGhlci1jbGllbnQxFTATBgNVBAoMDFN5bXBob255VGVzdDCCASIwDQYJKoZI
hvcNAQEBBQADggEPADCCAQoCggEBAN01SW1PSp8c334f3yL7ft+FIaHxz2dN3zwE
s2LA8nepPQ/r0Gf0IvChLC7u2HFPqrr8G9bM4+HiG4IhkiVi9NKOOJqjSN3Lam2/
vhRTBxdhs4kk9vtr+1poUPz5kYJh01rikv/u7QgriYWJPUhkwIPWb1bIpAnBTlwA
o07ZmNN9RJd6uH7fk+Xf4hICATqB8d9WJMFDgMzhZmZ6NfAmo41tqvZKAdUoz5RU
1VjJbwCdOELztKsKrLPDQUvnPXhzEy+8tYHCFrFv8eFbD5dy6mi9feeORBIWj7NO
D0U+TwNU/6kiIetZWeLqr6cndFoNQkzVxsbOAJya9Ua5Iy6L1FECAwEAAaNyMHAw
CQYDVR0TBAIwADAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwIw
HQYDVR0OBBYEFC5r2mMAN/5phWHCGdfkrAEMonejMB8GA1UdIwQYMBaAFDawrRwb
XJ+BgOEp2umE+cXti/tsMA0GCSqGSIb3DQEBCwUAA4IBAQBBwSGaEOG/AVzOmWCr
LLVkxJ4PhbY8++Zl9JibMXrCc4DA5jlPHix0YOlFFk4ArSQRH1TmxEPlvjP2Itr6
vzPNcAU1/AvfwIRTKYQbAobKblTFnL9f9enG1HC0/MoeE3flj9g/Spz4at+hYzMG
r2KJsWz2gBkfpS2Helt8fsoH5mubglmRCk+C6hwuEV6h6EOu7zR/P+F7p/6f3PQa
ZfIN/AllCl7manc72G5XA0gl8QMosL8FewYYlXTyUmWVEjqV3nH63lD/vZtWYpUr
y9L+fMyg1yAItytHFc3HNyxrHE2+1CspX6YzOrqU/BuR4mgpWRq76RN+63BlxTMl
5t1U
-----END CERTIFICATE-----`,
	clientKey: `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDdNUltT0qfHN9+
H98i+37fhSGh8c9nTd88BLNiwPJ3qT0P69Bn9CLwoSwu7thxT6q6/BvWzOPh4huC
IZIlYvTSjjiao0jdy2ptv74UUwcXYbOJJPb7a/taaFD8+ZGCYdNa4pL/7u0IK4mF
iT1IZMCD1m9WyKQJwU5cAKNO2ZjTfUSXerh+35Pl3+ISAgE6gfHfViTBQ4DM4WZm
ejXwJqONbar2SgHVKM+UVNVYyW8AnThC87SrCqyzw0FL5z14cxMvvLWBwhaxb/Hh
Ww+XcupovX3njkQSFo+zTg9FPk8DVP+pIiHrWVni6q+nJ3RaDUJM1cbGzgCcmvVG
uSMui9RRAgMBAAECggEALA+3JnzKwlK/+aFjktZBeUhNYLKHu235bz0Idj00jr05
GnjANFSeuQuBf3+3wSo7Oa+J5Ak/wviEvjDtqWDCn0YQ5Ext8S/ZbS7qL6YyHWgq
mMCyKXZixKlOqHUVlMDjlpDW8v+mWyBA7kZd3JOk/R2zY7fnZMIKV60Q2l3hYQ6N
tr5pjbfGARkas27gT0pP/kEM8z5EjO3XwVE7ilmPTLqJHN9cY0gEvPL5mmF6Uu8Q
ye7RvG2bhPIIoBVbZJpI7bxigO2mnoR4P1f9mvaJ61spkisR3pfhdmXjoiqy/7lg
nnfg28ICQ2SwAqEvYHnWuRuwj6dGvcOdbLLMSIvauQKBgQD574cdI5E66tyFyE5g
Y8jzMrhfTd/WxJVRLYRlSQZ6kjiVM17KmE/W5wZUkAxLUHpZnynF315qjgD3ca21
4a563T5IZeOizDbqjNcqk4Bi8ZHuxYQudozviiVeQEfLBySblBlDlK7xt/PrmgM6
1kOre6RUQxnUDoFy2z5HKPwXrwKBgQDik1GJeBGZP27pC0TfCoW09zILfrNT1sCi
6GEl48euzM+zNXnhLDWm4XolXvnXPKPqHLeLWBlz3qilWrcgthK721AFsdmFCC/q
CQI/j0KQNslAWYaIutdmsg4tT9Sk9lZt4/9t5aakJkckjNLq/+Z41U2negTsfFNC
e3pemoXT/wKBgQDn6JNMPFZjfs1D7UqcMbqhvmxJMi8CTsHl4wA4Ivw5+zc5acMI
5S8fzpmXGVnvACumwQK3sb0fzcej0f1HCLMnGebSsof35NkH5cs4nEjChjfMf8VY
f3PiSCLIQ4jaIDSdj1up02pIq1FPSUa571o24bDm5qQumY8PjdNJoAPZzQKBgQDd
jVhpp/Lte02kq9RIlS1xa1aQTvBjxtbPdZOpTTZxAu0GPABV4rkD2e9qo5iCk1Vl
E3eW1irtVohqSG5RmjhvYWC6cNJWd08C9pQwOpHIGwpn1iLriGggj3O1cx5nwEl7
Yzrd53YvhQ6D+wAzss9W0J0CaxptdJSlqcBayZabWQKBgDC3k8OVbC/Yqu3EP0Zn
ImfaP+RWdeTc/p12iw5Nhdae9ysWzkJjqnVuKpS70reSz1q0PbVO3fIpieYGD3zZ
QATR522/6bbc+Mhs2My3kFJiOCPeHZpHyu7lU7Z0VmYJXbFhQrxhpggsCC81yOT6
w2EPe5AvnptfwD9cZDbA6PUz
-----END PRIVATE KEY-----`,
};

/**
 * Return the pre-baked CA + client cert for mTLS tests. Never null (static fixtures,
 * no openssl at runtime). Pass `other: true` for a client signed by a *different* CA.
 */
export function generateClientCa(other = false): ClientCa {
	return other ? OTHER_CLIENT_CA : CLIENT_CA;
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
	/** Client certificate (PEM) presented to the server for mTLS. */
	clientCert?: string;
	/** Client private key (PEM), required with clientCert. */
	clientKey?: string;
}): Promise<Buffer> {
	return new Promise((resolve, reject) => {
		const { port, host = '127.0.0.1', servername, caCert, data, rejectUnauthorized = false, clientCert, clientKey } = opts;
		const socket = tls.connect(
			{ port, host, servername, ca: caCert, rejectUnauthorized, cert: clientCert, key: clientKey },
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
