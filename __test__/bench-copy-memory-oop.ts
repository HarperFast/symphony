/**
 * Out-of-process memory benchmark: resident bytes per connection in symphony-server under parked,
 * active fan-out, slow-reader and churn-then-drop load, across allocator and buffer arms.
 *
 * symphony-server runs in its own process — in its own cgroup with swap disabled when
 * `systemd-run --user` works — while the TLS clients and the UDS upstreams run in separate processes.
 * Only symphony's process is sampled. The in-process benchmarks measured their own load generator's
 * memory, not the proxy's; do not fold this back into one process.
 *
 *   npm run build                      # release build; never benchmark a debug addon
 *   npm run build:bench-system-allocator   # the glibc-allocator build every arm but rust-jemalloc runs
 *   npm run benchmark:memory-oop -- --conns 100000 --repeats 3
 *
 * On a shared host, run it under whatever serialises benchmarks there. `--help` lists the options.
 *
 * Roles: the orchestrator (default) forks `--role client` and `--role upstream` copies of this file,
 * plus, for the slow-reader phase, a small python3 client (SLOW_CLIENT_PY) that can set SO_RCVBUF.
 */

import { fork, spawn, spawnSync, type ChildProcess } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
	copyFileSync,
	cpSync,
	createWriteStream,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	realpathSync,
	rmSync,
	writeFileSync,
} from 'node:fs';
import { get as httpGet } from 'node:http';
import { connect as netConnect, createServer as createNetServer, type Socket } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { connect as tlsConnect, type TLSSocket } from 'node:tls';

const ROOT = resolve(__dirname, '..', '..');
const SNI = 'bench.local';
const TICK_MS = 50;
const IPC_TIMEOUT_MS = 15_000;
// symphony's default ipAffinityTtlMs plus its 60 s sweep: per-IP state still live before this.
const AFFINITY_RECLAIM_MS = 300_000 + 60_000;

// ── Options ───────────────────────────────────────────────────────────────────

type PhaseKind = 'abc' | 'd' | 'soak' | 'cpu';
const PHASE_KINDS: PhaseKind[] = ['abc', 'd', 'soak', 'cpu'];

interface Options {
	conns: number;
	clients: number;
	upstreams: number;
	openRate: number;
	closeRate: number;
	maxInflight: number;
	burstSize: number;
	msgRate: number;
	msgSize: number;
	pingIntervalMs: number;
	pingSize: number;
	slowFraction: number;
	slowMsgRate: number;
	slowRcvbuf: number;
	slowMss: number;
	churnTurnoverS: number;
	dropFraction: number;
	settleMs: number;
	activeHoldMs: number;
	slowHoldMs: number;
	peakHoldMs: number;
	dropHoldMs: number;
	trimIntervalMs: number;
	tlsBufferLimit: number;
	sourceHeader: 'proxyProtocol' | 'none';
	ipAffinity: boolean;
	readBufferSize?: number;
	clientReadBufferSize?: number;
	upstreamReadBufferSize?: number;
	workerThreads?: number;
	cycles: number;
	troughHoldMs: number;
	cpuWindowMs: number;
	cpuWindows: number;
	symphonyCpus?: string;
	fixedOrder: boolean;
	arms: string[];
	phases: PhaseKind[];
	repeats: number;
	jemalloc: string;
	mimalloc?: string;
	rustJemallocAddon: string;
	/** A `--no-default-features` build: the allocator every arm except rust-jemalloc runs on. */
	systemAddon?: string;
	/** Extra arms that differ only by addon build, `--addon-arm name=path`. */
	addonArms: Record<string, string>;
	/** Extra environment per arm, `--arm-env name:KEY=VALUE`. */
	armEnv: Record<string, Record<string, string>>;
	out: string;
	cgroup: boolean;
	minAvailableMb: number;
}

const ALL_ARMS = [
	'glibc',
	'arena2',
	'trim',
	'jemalloc-preload',
	'mimalloc-preload',
	'rust-jemalloc',
	'buflimit',
	'buf-small',
];

const HELP = `Options (defaults in brackets):
  --conns N                 peak connections [30000]
  --clients M               client processes [ceil(conns / 12500)]
  --upstreams K             UDS upstream processes, one socket each [4]
  --open-rate R             new connections/s, all clients together [2000]
  --close-rate R            closes/s when dropping [4000]
  --burst-size B            bytes each client sends after its handshake, echoed back [512]
  --msg-rate R              upstream→client messages per connection per second [1]
  --msg-size B              message size [256]
  --ping-interval-ms T      client→upstream ping per connection, echoed back [30000]
  --ping-size B             [8]
  --slow-fraction F         fraction of the connections that stop reading in the slow phase [0.1]
  --slow-msg-rate R         extra messages/s the upstream sends each stalled connection, so its queues
                            fill within the hold instead of hours [50]; needs --source-header proxyProtocol
  --slow-rcvbuf B           SO_RCVBUF of the stalled connections [4096]
  --slow-mss B              TCP_MAXSEG of the stalled connections: symphony sizes its send buffer from
                            the MSS, and loopback's 64 KiB MSS would give every socket ~2.6 MB [1448]
  --churn-turnover-s S      churn closes+reopens the whole population every S seconds [300]
  --drop-fraction F         fraction of peak kept after the drop [0.1]
  --settle-ms / --active-hold-ms / --slow-hold-ms / --peak-hold-ms / --drop-hold-ms
                            [15000 / 90000 / 120000 / 60000 / 390000 — past the affinity TTL + sweep]
  --trim-interval-ms T      malloc_trim(0) period for the trim arm [30000]
  --tls-buffer-limit B      rustls buffer limit for the buflimit arm [16384]
  --source-header H         proxyProtocol | none [proxyProtocol]
  --no-ip-affinity          configure the UDS upstreams without ipAffinity
  --read-buffer-size, --client-read-buffer-size, --upstream-read-buffer-size, --worker-threads
                            passed through to the symphony config [unset: symphony defaults]
  --arms a,b,...            ${ALL_ARMS.join(', ')}
                            [every arm whose prerequisites exist]
  --phases abc,d            abc = parked → active → slow in one process; d = churn-then-drop [abc,d]
                            soak = --cycles of churned ramp to --conns, --peak-hold-ms, drop to
                            --drop-fraction, --trough-hold-ms; cpu = --conns parked, then --cpu-windows
                            windows of --cpu-window-ms at --msg-rate with no pings: symphony CPU s per GB
                            and per 1M messages, and delivery latency (upstream write → client read)
  --cycles N                soak cycles [5]
  --trough-hold-ms T        soak hold at each trough [390000]
  --cpu-window-ms T / --cpu-windows N   [60000 / 3]
  --symphony-cpus LIST      run symphony under taskset -c LIST (pin the orchestrator elsewhere yourself)
  --fixed-order             run arms in --arms order every repeat instead of shuffling
  --repeats N               [3]
  --jemalloc PATH           LD_PRELOAD library [/usr/lib/<arch>-linux-gnu/libjemalloc.so.2]
  --mimalloc PATH           LD_PRELOAD library for mimalloc-preload [none]
  --rust-jemalloc-addon P   .node with jemalloc as its Rust allocator [the default build in the repo root]
  --system-addon P          .node built without it, for every other arm (npm run build:bench-system-allocator)
                            [target/bench-system-allocator/symphony.linux-<arch>-gnu.node if present]
  --addon-arm NAME=PATH     an extra arm running another .node build on whichever Rust allocator it was
                            built with, for comparing a native change; only the .node is swapped, the JS is this
                            checkout's dist/; repeatable, and included in the default arm list
  --arm-env NAME:KEY=VALUE  extra environment for one arm, e.g. an --addon-arm with
                            _RJEM_MALLOC_CONF=background_thread:true; repeatable
  --out DIR                 results root; each invocation writes a timestamped directory under it
                            [$TMPDIR/symphony-memory-oop, else ./bench-results]
  --no-cgroup               run symphony without its own systemd scope
  --min-available-mb M      abort a run when host or cgroup headroom drops below this [1536]
  --summarize DIR...        print the summary of earlier invocations' output directories together
`;

function argValue(argv: string[], name: string): string | undefined {
	const i = argv.indexOf(name);
	return i >= 0 ? argv[i + 1] : undefined;
}

function parseOptions(argv: string[]): Options {
	if (argv.includes('--help')) {
		process.stdout.write(HELP);
		process.exit(0);
	}
	const num = (name: string, fallback: number): number => {
		const raw = argValue(argv, name);
		if (raw === undefined) return fallback;
		const value = Number(raw);
		if (!Number.isFinite(value) || value < 0) throw new Error(`${name} must be a non-negative number, got '${raw}'`);
		return value;
	};
	const optionalNum = (name: string): number | undefined =>
		argValue(argv, name) === undefined ? undefined : num(name, 0);
	const conns = num('--conns', 30000);
	const libArch = process.arch === 'arm64' ? 'aarch64' : 'x86_64';
	const defaultSystemAddon = join(ROOT, 'target', 'bench-system-allocator', `symphony.linux-${process.arch}-gnu.node`);
	const sourceHeader = argValue(argv, '--source-header') ?? 'proxyProtocol';
	if (sourceHeader !== 'proxyProtocol' && sourceHeader !== 'none') {
		throw new Error(`--source-header must be proxyProtocol or none, got '${sourceHeader}'`);
	}
	const phases = (argValue(argv, '--phases') ?? 'abc,d').split(',');
	for (const phase of phases) {
		if (!PHASE_KINDS.includes(phase as PhaseKind))
			throw new Error(`--phases takes ${PHASE_KINDS.join(', ')}, got '${phase}'`);
	}
	const opts: Options = {
		conns,
		clients: Math.max(1, num('--clients', Math.ceil(conns / 12500))),
		upstreams: Math.min(64, Math.max(1, Math.floor(num('--upstreams', 4)))),
		openRate: num('--open-rate', 2000),
		closeRate: num('--close-rate', 4000),
		maxInflight: num('--max-inflight', 200),
		burstSize: num('--burst-size', 512),
		msgRate: num('--msg-rate', 1),
		msgSize: num('--msg-size', 256),
		pingIntervalMs: num('--ping-interval-ms', 30000),
		pingSize: num('--ping-size', 8),
		slowFraction: num('--slow-fraction', 0.1),
		slowMsgRate: num('--slow-msg-rate', 50),
		slowRcvbuf: num('--slow-rcvbuf', 4096),
		slowMss: num('--slow-mss', 1448),
		churnTurnoverS: num('--churn-turnover-s', 300),
		dropFraction: num('--drop-fraction', 0.1),
		settleMs: num('--settle-ms', 15000),
		activeHoldMs: num('--active-hold-ms', 90000),
		slowHoldMs: num('--slow-hold-ms', 120000),
		peakHoldMs: num('--peak-hold-ms', 60000),
		dropHoldMs: num('--drop-hold-ms', AFFINITY_RECLAIM_MS + 30_000),
		trimIntervalMs: num('--trim-interval-ms', 30000),
		tlsBufferLimit: num('--tls-buffer-limit', 16384),
		sourceHeader,
		ipAffinity: !argv.includes('--no-ip-affinity'),
		readBufferSize: optionalNum('--read-buffer-size'),
		clientReadBufferSize: optionalNum('--client-read-buffer-size'),
		upstreamReadBufferSize: optionalNum('--upstream-read-buffer-size'),
		workerThreads: optionalNum('--worker-threads'),
		cycles: Math.max(1, num('--cycles', 5)),
		troughHoldMs: num('--trough-hold-ms', AFFINITY_RECLAIM_MS + 30_000),
		cpuWindowMs: num('--cpu-window-ms', 60_000),
		cpuWindows: Math.max(1, num('--cpu-windows', 3)),
		symphonyCpus: argValue(argv, '--symphony-cpus'),
		fixedOrder: argv.includes('--fixed-order'),
		arms: [],
		phases: phases as PhaseKind[],
		repeats: Math.max(1, num('--repeats', 3)),
		jemalloc: argValue(argv, '--jemalloc') ?? `/usr/lib/${libArch}-linux-gnu/libjemalloc.so.2`,
		mimalloc: argValue(argv, '--mimalloc'),
		rustJemallocAddon: argValue(argv, '--rust-jemalloc-addon') ?? rootAddon(),
		systemAddon: argValue(argv, '--system-addon') ?? (existsSync(defaultSystemAddon) ? defaultSystemAddon : undefined),
		addonArms: Object.fromEntries(
			argv
				.flatMap((arg, i) => (arg === '--addon-arm' ? [argv[i + 1] ?? ''] : []))
				.map((spec) => {
					const eq = spec.indexOf('=');
					const name = spec.slice(0, eq);
					if (eq <= 0) throw new Error(`--addon-arm takes NAME=PATH, got '${spec}'`);
					// Names become directory and systemd unit names, and must not shadow a built-in arm.
					if (!/^[a-z0-9-]+$/.test(name) || ALL_ARMS.includes(name)) {
						throw new Error(`--addon-arm name '${name}' must be new and use only a-z, 0-9 and -`);
					}
					return [name, resolve(spec.slice(eq + 1))];
				})
		),
		armEnv: argv
			.flatMap((arg, i) => (arg === '--arm-env' ? [argv[i + 1] ?? ''] : []))
			.reduce<Record<string, Record<string, string>>>((all, spec) => {
				const m = /^([a-z0-9-]+):([A-Za-z_][A-Za-z0-9_]*)=(.*)$/.exec(spec);
				if (!m) throw new Error(`--arm-env takes NAME:KEY=VALUE, got '${spec}'`);
				(all[m[1]] ??= {})[m[2]] = m[3];
				return all;
			}, {}),
		out: resolve(
			argValue(argv, '--out') ??
				(process.env.TMPDIR ? join(process.env.TMPDIR, 'symphony-memory-oop') : join(ROOT, 'bench-results'))
		),
		cgroup: !argv.includes('--no-cgroup'),
		minAvailableMb: num('--min-available-mb', 1536),
	};
	if (opts.slowMsgRate > 0 && opts.sourceHeader !== 'proxyProtocol') {
		throw new Error(
			'--slow-msg-rate needs --source-header proxyProtocol: the upstream finds stalled connections by source address'
		);
	}
	if (opts.slowFraction >= 1) throw new Error('--slow-fraction must be below 1');
	if (opts.phases.includes('cpu') && !(Number.isInteger(opts.msgSize) && opts.msgSize >= 8)) {
		throw new Error('--phases cpu needs an integer --msg-size >= 8: each message carries an 8-byte send timestamp');
	}
	if (opts.slowFraction > 0 && spawnSync('python3', ['--version']).status !== 0) {
		throw new Error('the slow-reader phase needs python3 (or pass --slow-fraction 0)');
	}
	if (opts.clients >= SLOW_NET - 1)
		throw new Error(`--clients must be below ${SLOW_NET - 1}: their source nets would overlap the slow readers'`);
	const requested = argValue(argv, '--arms');
	opts.arms = requested
		? requested.split(',')
		: [...ALL_ARMS, ...Object.keys(opts.addonArms)].filter((arm) => armUnavailable(arm, opts) === undefined);
	for (const arm of opts.arms) {
		const reason = armUnavailable(arm, opts);
		if (reason) throw new Error(`arm '${arm}' unavailable: ${reason}`);
	}
	return opts;
}

// ── Arms ──────────────────────────────────────────────────────────────────────

interface Arm {
	name: string;
	env: Record<string, string>;
	/** Overrides merged into the proxy config. */
	config: Record<string, number>;
	/** A `.node` built with a different feature set; staged next to a copy of `dist/`. */
	addon?: string;
	/** A library that must show up in symphony's memory map, proving the arm is what ran. */
	mustMap?: string;
	phases: PhaseKind[];
}

function armUnavailable(name: string, opts: Options): string | undefined {
	if (Object.hasOwn(opts.addonArms, name))
		return existsSync(opts.addonArms[name]) ? undefined : `${opts.addonArms[name]} not found`;
	if (name === 'rust-jemalloc') {
		if (!existsSync(opts.rustJemallocAddon)) return `${opts.rustJemallocAddon} not found`;
		return isJemallocBuild(opts.rustJemallocAddon)
			? undefined
			: `${opts.rustJemallocAddon} was built without its jemalloc feature`;
	}
	if (!ALL_ARMS.includes(name)) return 'unknown arm';
	if (!opts.systemAddon || !existsSync(opts.systemAddon)) {
		return 'no --system-addon (npm run build:bench-system-allocator)';
	}
	if (isJemallocBuild(opts.systemAddon)) return `${opts.systemAddon} has jemalloc as its Rust allocator`;
	switch (name) {
		case 'trim':
			return process.report?.getReport && (process.report.getReport() as any).header.glibcVersionRuntime
				? undefined
				: 'malloc_trim needs glibc';
		case 'jemalloc-preload':
			return existsSync(opts.jemalloc) ? undefined : `${opts.jemalloc} not found (--jemalloc)`;
		case 'mimalloc-preload':
			return opts.mimalloc && existsSync(opts.mimalloc) ? undefined : 'no --mimalloc library given';
		default:
			return undefined;
	}
}

const rootAddon = (): string => join(ROOT, `symphony.linux-${process.arch}-gnu.node`);

/** Statically linked, so it never shows up in /proc/<pid>/maps; its message prefix does in the file. */
const isJemallocBuild = (addon: string): boolean => readFileSync(addon).includes('<jemalloc>');

function resolveArm(name: string, opts: Options): Arm {
	const arm: Arm = {
		name,
		env: {},
		config: {},
		phases: opts.phases,
		addon: opts.addonArms[name] ?? (name === 'rust-jemalloc' ? opts.rustJemallocAddon : opts.systemAddon),
	};
	switch (name) {
		case 'arena2':
			arm.env.MALLOC_ARENA_MAX = '2';
			break;
		case 'trim':
			arm.env.SYMPHONY_MALLOC_TRIM_INTERVAL_MS = String(opts.trimIntervalMs);
			arm.env.RUST_LOG = 'symphony::bench_hooks=info';
			break;
		case 'jemalloc-preload':
			arm.env.LD_PRELOAD = opts.jemalloc;
			arm.mustMap = opts.jemalloc;
			break;
		case 'mimalloc-preload':
			arm.env.LD_PRELOAD = opts.mimalloc!;
			arm.mustMap = opts.mimalloc;
			break;
		case 'buflimit':
			arm.env.SYMPHONY_TLS_BUFFER_LIMIT = String(opts.tlsBufferLimit);
			// The queue cap only matters where queues form: active fan-out and slow readers.
			arm.phases = opts.phases.filter((p) => p === 'abc');
			break;
		case 'buf-small':
			// The README's MQTT sizing. Against glibc it prices how much of the copy buffers is resident.
			arm.config = { clientReadBufferSize: 1024, upstreamReadBufferSize: 4096 };
			break;
	}
	Object.assign(arm.env, opts.armEnv[name]);
	return arm;
}

// ── IPC between the orchestrator and its children ─────────────────────────────

type ClientCommand =
	| { type: 'target'; live: number }
	| { type: 'rates'; open: number; close: number }
	| { type: 'churn'; turnoverS: number }
	| { type: 'pause' }
	| { type: 'resume' }
	| { type: 'ping'; intervalMs: number; size: number }
	| { type: 'latency'; msgSize: number }
	| { type: 'stats'; seq: number }
	| { type: 'exit' };

interface ClientStats {
	live: number;
	inflight: number;
	paused: number;
	opened: number;
	failed: number;
	closed: number;
	/** Established connections that ended without this client closing them. */
	lost: number;
	bytesIn: number;
	bytesOut: number;
	rss: number;
	/** Delivery latency histogram (LATENCY_BUCKETS), when stamped messages are on. */
	latency?: number[];
}

type UpstreamCommand =
	| { type: 'push'; rate: number; size: number; stamp?: boolean }
	| { type: 'slow'; rate: number }
	| { type: 'stats'; seq: number }
	| { type: 'exit' };

interface UpstreamStats {
	conns: number;
	sent: number;
	dropped: number;
	/** Of `sent`, the extra slow-phase messages to stalled connections. */
	slowSent: number;
	/** After the PROXY header. */
	bytesIn: number;
	bytesOut: number;
	rss: number;
}

/** Eight buckets per power of two of microseconds, ~9% wide. */
const LATENCY_BUCKETS = 8 * 32;
const latencyBucket = (micros: number): number =>
	Math.min(LATENCY_BUCKETS - 1, Math.max(0, Math.floor(Math.log2(Math.max(1, micros)) * 8)));
const bucketMicros = (bucket: number): number => 2 ** ((bucket + 1) / 8);

function percentileMicros(histogram: number[], fraction: number): number {
	const total = histogram.reduce((a, b) => a + b, 0);
	if (total === 0) return NaN;
	let seen = 0;
	for (let i = 0; i < histogram.length; i++) {
		seen += histogram[i];
		if (seen >= total * fraction) return bucketMicros(i);
	}
	return bucketMicros(histogram.length - 1);
}

const emptyClientStats = (): ClientStats => ({
	live: 0,
	inflight: 0,
	paused: 0,
	opened: 0,
	failed: 0,
	closed: 0,
	lost: 0,
	bytesIn: 0,
	bytesOut: 0,
	rss: 0,
});
const emptyUpstreamStats = (): UpstreamStats => ({
	conns: 0,
	sent: 0,
	dropped: 0,
	slowSent: 0,
	bytesIn: 0,
	bytesOut: 0,
	rss: 0,
});

/**
 * Source addresses are 127.<net>.x.y: Node clients take nets 1..199, slow-reader processes 200 and
 * up, which is how the upstream recognises a stalled connection from its PROXY header.
 */
const SLOW_NET = 200;

// ── Client role ───────────────────────────────────────────────────────────────

interface ClientConn {
	socket: TLSSocket;
	/** Position in `live`; -1 once removed. */
	index: number;
	closing: boolean;
	/** Stamped-message framing: echoed burst bytes still to skip, offset in the current message. */
	skip: number;
	pos: number;
	stamp?: Buffer;
}

function runClient(argv: string[]): void {
	const id = Number(argValue(argv, '--id'));
	const port = Number(argValue(argv, '--port'));
	const maxInflight = Number(argValue(argv, '--max-inflight'));
	const burst = Buffer.alloc(Number(argValue(argv, '--burst')), 0x61);
	const live: ClientConn[] = [];
	const stats = emptyClientStats();
	let target = 0;
	let openRate = 0;
	let closeRate = 0;
	let openBudget = 0;
	let closeBudget = 0;
	let churnTurnoverS = 0;
	let churnBudget = 0;
	let pingIntervalMs = 0;
	let pingBudget = 0;
	let pingCursor = 0;
	let ping = Buffer.alloc(0);
	let nextSlot = 0;
	let stampedSize = 0;
	let latency: number[] | undefined;

	// The upstream's first 8 bytes of each message are its CLOCK_MONOTONIC write time, shared host-wide.
	const readStamps = (conn: ClientConn, chunk: Buffer): void => {
		const now = process.hrtime.bigint();
		let i = Math.min(conn.skip, chunk.length);
		conn.skip -= i;
		while (i < chunk.length) {
			const n = Math.min((conn.pos < 8 ? 8 : stampedSize) - conn.pos, chunk.length - i);
			if (conn.pos < 8) {
				chunk.copy(conn.stamp!, conn.pos, i, i + n);
				if (conn.pos + n === 8) latency![latencyBucket(Number(now - conn.stamp!.readBigUInt64LE(0)) / 1000)]++;
			}
			conn.pos += n;
			i += n;
			if (conn.pos === stampedSize) conn.pos = 0;
		}
	};

	const remove = (conn: ClientConn): void => {
		if (conn.index < 0) return;
		const last = live.pop()!;
		if (last !== conn) {
			live[conn.index] = last;
			last.index = conn.index;
		}
		conn.index = -1;
	};

	const write = (conn: ClientConn, data: Buffer): void => {
		conn.socket.write(data, (err) => {
			if (!err) stats.bytesOut += data.length;
		});
	};

	const open = (): void => {
		// One loopback source address per connection slot: 127/8 is all local on Linux, so this sidesteps
		// ephemeral-port exhaustion at 100k+ and gives symphony's per-IP state production's many-IPs shape.
		const slot = nextSlot++ % 65536;
		const localAddress = `127.${1 + id}.${slot >> 8}.${slot & 255}`; // see SLOW_NET
		stats.inflight++;
		let established = false;
		const tcp = netConnect({ host: '127.0.0.1', port, localAddress });
		const socket = tlsConnect({ socket: tcp, servername: SNI, rejectUnauthorized: false });
		const conn: ClientConn = {
			socket,
			index: -1,
			closing: false,
			skip: burst.length,
			pos: 0,
			stamp: stampedSize ? Buffer.alloc(8) : undefined,
		};
		socket.on('secureConnect', () => {
			established = true;
			stats.inflight--;
			stats.opened++;
			conn.index = live.length;
			live.push(conn);
			write(conn, burst);
		});
		socket.on('data', (chunk: Buffer) => {
			stats.bytesIn += chunk.length;
			if (conn.stamp) readStamps(conn, chunk);
		});
		socket.on('error', () => {});
		socket.on('close', () => {
			if (!established) {
				stats.inflight--;
				stats.failed++;
			} else if (!conn.closing) {
				stats.lost++;
			}
			remove(conn);
		});
	};

	const closeRandom = (): void => {
		const conn = live[Math.floor(Math.random() * live.length)];
		remove(conn);
		conn.closing = true;
		stats.closed++;
		conn.socket.end(); // graceful: symphony sees EOF and tears down both halves
	};

	let last = performance.now();
	setInterval(() => {
		const now = performance.now();
		const dt = (now - last) / 1000;
		last = now;

		if (churnTurnoverS > 0) {
			churnBudget = Math.min(churnBudget + (live.length / churnTurnoverS) * dt, live.length);
			while (churnBudget >= 1 && live.length > 0) {
				churnBudget--;
				closeRandom(); // the deficit is reopened below, at the open rate
			}
		}

		openBudget = Math.min(openBudget + openRate * dt, Math.max(1, openRate));
		while (openBudget >= 1 && live.length + stats.inflight < target && stats.inflight < maxInflight) {
			openBudget--;
			open();
		}

		closeBudget = Math.min(closeBudget + closeRate * dt, Math.max(1, closeRate));
		while (closeBudget >= 1 && live.length > target) {
			closeBudget--;
			closeRandom();
		}

		if (pingIntervalMs > 0 && live.length > 0) {
			pingBudget = Math.min(pingBudget + (live.length * dt * 1000) / pingIntervalMs, live.length);
			while (pingBudget >= 1) {
				pingBudget--;
				write(live[pingCursor++ % live.length], ping);
			}
		}
	}, TICK_MS);

	process.on('message', (raw: unknown) => {
		const msg = raw as ClientCommand;
		switch (msg.type) {
			case 'target':
				target = msg.live;
				break;
			case 'rates':
				openRate = msg.open;
				closeRate = msg.close;
				break;
			case 'churn':
				churnTurnoverS = msg.turnoverS;
				churnBudget = 0;
				break;
			case 'ping':
				pingIntervalMs = msg.intervalMs;
				ping = Buffer.alloc(msg.size, 0x70);
				pingBudget = 0;
				break;
			case 'latency':
				stampedSize = msg.msgSize;
				latency = new Array(LATENCY_BUCKETS).fill(0);
				break;
			case 'stats':
				stats.live = live.length;
				stats.rss = process.memoryUsage.rss();
				stats.latency = latency;
				process.send!({ type: 'stats', seq: msg.seq, stats });
				break;
			case 'exit':
				for (const conn of live) conn.socket.destroy();
				process.exit(0);
		}
	});
	process.on('disconnect', () => process.exit(0));
	process.send!({ type: 'ready' });
}

// ── Upstream role ─────────────────────────────────────────────────────────────

interface UpstreamConn {
	socket: Socket;
	index: number;
	/** From a slow-reader process, by the PROXY header's source address. */
	slow: boolean;
	/** Bytes received before the PROXY v1 line ended; undefined once it has. */
	header?: Buffer;
	/** Burst bytes not yet echoed. A stamped message must not precede them: the client frames after them. */
	burstPending: number;
}

function runUpstream(argv: string[]): void {
	const path = argValue(argv, '--socket')!;
	const burst = Number(argValue(argv, '--burst'));
	const expectHeader = argValue(argv, '--source-header') === 'proxyProtocol';
	const conns: UpstreamConn[] = [];
	const stats = emptyUpstreamStats();
	let msg = Buffer.alloc(0);
	let stamp = false;
	let rate = 0;
	let budget = 0;
	let cursor = 0;
	const slowConns: UpstreamConn[] = [];
	let slowRate = 0;
	let slowBudget = 0;
	let slowCursor = 0;

	const send = (conn: UpstreamConn): boolean => {
		// A backed-up socket drops the message, as a QoS-0 broker would; queuing it here would only
		// grow the upstream's memory, which is not what this benchmark measures.
		if (conn.socket.writableNeedDrain) {
			stats.dropped++;
			return false;
		}
		if (stamp && conn.burstPending > 0) return false;
		let sent = msg;
		if (stamp) {
			sent = Buffer.from(msg);
			sent.writeBigUInt64LE(process.hrtime.bigint(), 0);
		}
		conn.socket.write(sent, (err) => {
			if (!err) stats.bytesOut += sent.length;
		});
		stats.sent++;
		return true;
	};

	const server = createNetServer((socket) => {
		const conn: UpstreamConn = {
			socket,
			index: conns.length,
			slow: false,
			header: expectHeader ? Buffer.alloc(0) : undefined,
			burstPending: burst,
		};
		conns.push(conn);
		socket.on('data', (chunk: Buffer) => {
			if (conn.header) {
				const pending = Buffer.concat([conn.header, chunk]);
				const end = pending.indexOf('\r\n');
				if (end < 0) {
					conn.header = pending;
					return;
				}
				conn.header = undefined;
				// PROXY TCP4 <src> <dst> <sport> <dport>
				const src = pending.subarray(0, end).toString('latin1').split(' ')[2]?.split('.');
				if (src?.length === 4 && Number(src[1]) >= SLOW_NET) {
					conn.slow = true;
					slowConns.push(conn);
				}
				chunk = pending.subarray(end + 2);
				if (chunk.length === 0) return;
			}
			stats.bytesIn += chunk.length;
			conn.burstPending = Math.max(0, conn.burstPending - chunk.length);
			const echoed = chunk;
			// Echoed: the burst and pings come back like a broker's acks.
			socket.write(echoed, (err) => {
				if (!err) stats.bytesOut += echoed.length;
			});
		});
		socket.on('error', () => {});
		socket.on('close', () => {
			const last = conns.pop()!;
			if (last !== conn) {
				conns[conn.index] = last;
				last.index = conn.index;
			}
			if (conn.slow) slowConns.splice(slowConns.indexOf(conn), 1);
		});
	});
	server.on('error', (err) => {
		console.error(`upstream ${path}: ${err.message}`);
		process.exit(1);
	});
	server.listen(path, () => process.send!({ type: 'ready' }));

	let last = performance.now();
	setInterval(() => {
		const now = performance.now();
		const dt = (now - last) / 1000;
		last = now;
		if (conns.length === 0) return;
		if (rate > 0) {
			budget = Math.min(budget + conns.length * rate * dt, conns.length);
			while (budget >= 1) {
				budget--;
				send(conns[cursor++ % conns.length]);
			}
		}
		if (slowRate > 0 && slowConns.length > 0) {
			slowBudget = Math.min(slowBudget + slowConns.length * slowRate * dt, slowConns.length * slowRate);
			while (slowBudget >= 1) {
				slowBudget--;
				if (send(slowConns[slowCursor++ % slowConns.length])) stats.slowSent++;
			}
		}
	}, TICK_MS);

	process.on('message', (raw: unknown) => {
		const cmd = raw as UpstreamCommand;
		switch (cmd.type) {
			case 'push':
				rate = cmd.rate;
				stamp = cmd.stamp === true;
				msg = Buffer.alloc(cmd.size, 0x6d);
				budget = 0;
				break;
			case 'slow':
				slowRate = cmd.rate;
				slowBudget = 0;
				break;
			case 'stats':
				stats.conns = conns.length;
				stats.rss = process.memoryUsage.rss();
				process.send!({ type: 'stats', seq: cmd.seq, stats });
				break;
			case 'exit':
				process.exit(0);
		}
	});
	process.on('disconnect', () => process.exit(0));
}

// ── Slow-reader role (python3) ────────────────────────────────────────────────

/**
 * A client that can stall with a small receive window, so the backlog reaches symphony instead of
 * its own kernel. Node cannot set SO_RCVBUF on a TCP socket, and on recent kernels (7.0) an unlocked receive
 * buffer keeps growing while data arrives even if nothing reads it, so a paused Node socket absorbs
 * megabytes before symphony sees a closed window. A remote stalled reader closes it far sooner.
 * Speaks the client protocol as JSON lines on stdin/stdout: Node's IPC channel is unsupported with a
 * child that is not Node.
 */
const SLOW_CLIENT_PY = String.raw`
import json, os, selectors, socket, ssl, sys, time

args = dict(zip(sys.argv[1::2], sys.argv[2::2]))
port, net = int(args['--port']), int(args['--net'])
rcvbuf, mss = int(args['--rcvbuf']), int(args['--mss'])
burst = b'a' * int(args['--burst'])
cmd_in, cmd_out = 0, 1
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
sel = selectors.DefaultSelector()
live = set()
stats = dict(live=0, inflight=0, paused=0, opened=0, failed=0, closed=0, lost=0, bytesIn=0, bytesOut=0, rss=0)
state = dict(target=0, rate=0.0, budget=0.0, paused=False, slot=0)

def send(msg):
    data = (json.dumps(msg) + '\n').encode()
    while data:
        try:
            data = data[os.write(cmd_out, data):]
        except BlockingIOError:
            time.sleep(0.001)

def open_one():
    slot = state['slot'] % 65536
    state['slot'] += 1
    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        # Both before connect: the window scale and the MSS are fixed by the handshake.
        raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, rcvbuf)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG, mss)
        raw.bind(('127.%d.%d.%d' % (net, slot >> 8, slot & 255), 0))
        raw.settimeout(10)
        raw.connect(('127.0.0.1', port))
        conn = ctx.wrap_socket(raw, server_hostname=args['--sni'])
        conn.sendall(burst)
    except OSError:
        raw.close()
        stats['failed'] += 1
        return
    conn.setblocking(False)
    stats['opened'] += 1
    stats['bytesOut'] += len(burst)
    live.add(conn)
    if not state['paused']:
        sel.register(conn, selectors.EVENT_READ)

def forget(conn):
    live.discard(conn)
    try:
        sel.unregister(conn)
    except (KeyError, ValueError):
        pass
    conn.close()

def drain(conn):
    while True:
        try:
            data = conn.recv(65536)
        except ssl.SSLWantReadError:
            return
        except OSError:
            data = b''
        if not data:
            stats['lost'] += 1
            forget(conn)
            return
        stats['bytesIn'] += len(data)

def handle(msg):
    kind = msg['type']
    if kind == 'target':
        state['target'] = msg['live']
        while len(live) > state['target']:
            stats['closed'] += 1
            forget(next(iter(live)))
    elif kind == 'rates':
        state['rate'] = msg['open']
    elif kind == 'pause' and not state['paused']:
        state['paused'] = True
        for conn in live:
            sel.unregister(conn)
    elif kind == 'resume' and state['paused']:
        state['paused'] = False
        for conn in live:
            sel.register(conn, selectors.EVENT_READ)
    elif kind == 'stats':
        stats['live'] = len(live)
        stats['paused'] = len(live) if state['paused'] else 0
        with open('/proc/self/statm') as f:
            stats['rss'] = int(f.read().split()[1]) * os.sysconf('SC_PAGE_SIZE')
        send(dict(type='stats', seq=msg['seq'], stats=stats))
    elif kind == 'exit':
        sys.exit(0)

os.set_blocking(cmd_in, False)
sel.register(cmd_in, selectors.EVENT_READ, 'ipc')
pending = b''
send(dict(type='ready'))
last = time.monotonic()
while True:
    for key, _ in sel.select(0.05):
        if key.data != 'ipc':
            # A pause handled earlier in this same batch must stop the reads it returned too.
            if not state['paused'] and key.fileobj in live:
                drain(key.fileobj)
            continue
        try:
            chunk = os.read(cmd_in, 65536)
        except BlockingIOError:
            continue
        if not chunk:
            sys.exit(0)
        pending += chunk
        while b'\n' in pending:
            line, pending = pending.split(b'\n', 1)
            if line.strip():
                handle(json.loads(line))
    now = time.monotonic()
    state['budget'] = min(state['budget'] + state['rate'] * (now - last), max(1.0, state['rate']))
    last = now
    # Handshakes block, so open in small batches and get back to the IPC channel.
    for _ in range(50):
        if state['budget'] < 1 or len(live) >= state['target']:
            break
        state['budget'] -= 1
        open_one()
`;

// ── Sampling (symphony's process only) ────────────────────────────────────────

/** `Key:   123 kB` lines → bytes. */
function readKb(file: string): Record<string, number> {
	const out: Record<string, number> = {};
	for (const line of readFileSync(file, 'utf8').split('\n')) {
		const m = /^(\w+):\s+(\d+) kB$/.exec(line);
		if (m) out[m[1]] = Number(m[2]) * 1024;
	}
	return out;
}

let pageSize: number | undefined;
/** sockstat and tcp_mem count kernel pages, which are 64 KiB on some arm64 kernels. */
function pagesToBytes(pages: number): number {
	if (pageSize === undefined) {
		const size = Number(spawnSync('getconf', ['PAGESIZE'], { encoding: 'utf8' }).stdout);
		if (!(size > 0)) throw new Error('getconf PAGESIZE failed');
		pageSize = size;
	}
	return pages * pageSize;
}

function tcpMemBytes(): number {
	const m = /^TCP: .* mem (\d+)$/m.exec(readFileSync('/proc/net/sockstat', 'utf8'));
	if (!m) throw new Error('no TCP mem line in /proc/net/sockstat');
	return pagesToBytes(Number(m[1]));
}

interface SocketMem {
	sockets: number;
	/** Sums of skmem r (receive queue), w (queued for send) and f (forward-allocated). */
	rmem: number;
	wqueued: number;
	fwd: number;
	/** Largest rb (receive buffer limit) and tb (send buffer limit), after kernel autotuning. */
	maxRcvbuf: number;
	maxSndbuf: number;
	/** Sockets with a non-empty send queue (symphony side) or receive queue (client side). */
	backlogged: number;
}

let ssUnavailable: string | undefined;

/**
 * Kernel buffers of TCP sockets on the listener port: `sport` selects symphony's accepted sockets,
 * `dport` the clients' ends (context only — on a real network those live on other hosts). UDS
 * upstream queues are invisible to `ss -t`.
 */
function socketMem(port: number, side: 'sport' | 'dport'): SocketMem | undefined {
	if (ssUnavailable) return undefined;
	const res = spawnSync('ss', ['-tmnH', 'state', 'established', `( ${side} = :${port} )`], {
		encoding: 'utf8',
		maxBuffer: 1 << 30,
	});
	if (res.status !== 0) {
		ssUnavailable = res.error?.message ?? res.stderr;
		console.warn(`    ss unavailable (${ssUnavailable}); kernel socket figures skipped`);
		return undefined;
	}
	const out: SocketMem = { sockets: 0, rmem: 0, wqueued: 0, fwd: 0, maxRcvbuf: 0, maxSndbuf: 0, backlogged: 0 };
	const re = /skmem:\(r(\d+),rb(\d+),t\d+,tb(\d+),f(\d+),w(\d+),/g;
	for (let m = re.exec(res.stdout); m; m = re.exec(res.stdout)) {
		const [r, rb, tb, f, w] = m.slice(1).map(Number);
		out.sockets++;
		out.rmem += r;
		out.fwd += f;
		out.wqueued += w;
		out.maxRcvbuf = Math.max(out.maxRcvbuf, rb);
		out.maxSndbuf = Math.max(out.maxSndbuf, tb);
		if ((side === 'sport' ? w : r) > 0) out.backlogged++;
	}
	return out;
}

interface CgroupMem {
	current: number;
	anon: number;
	sock: number;
	kernel: number;
	file: number;
}

function cgroupMem(dir: string): CgroupMem {
	const stat: Record<string, number> = {};
	for (const line of readFileSync(join(dir, 'memory.stat'), 'utf8').split('\n')) {
		const [key, value] = line.split(' ');
		if (key) stat[key] = Number(value);
	}
	return {
		current: Number(readFileSync(join(dir, 'memory.current'), 'utf8')),
		anon: stat.anon,
		sock: stat.sock,
		kernel: stat.kernel,
		file: stat.file,
	};
}

function cgroupDirOf(pid: number): string {
	return join('/sys/fs/cgroup', readFileSync(`/proc/${pid}/cgroup`, 'utf8').trim().replace(/^0::/, ''));
}

/** Smallest memory.max − memory.current from `dir` up to the root: an ancestor's limit kills too. */
function cgroupHeadroomMb(dir: string): number {
	let headroom = Infinity;
	for (let d = dir; d.startsWith('/sys/fs/cgroup/'); d = dirname(d)) {
		try {
			const max = readFileSync(join(d, 'memory.max'), 'utf8').trim();
			if (max === 'max') continue;
			headroom = Math.min(headroom, Number(max) - Number(readFileSync(join(d, 'memory.current'), 'utf8')));
		} catch {
			// no memory controller at this level
		}
	}
	return headroom / 1048576;
}

interface ProcMem {
	vmRss: number;
	vmSwap: number;
	rssAnon: number;
	smapsRss: number;
	anonymous: number;
	privateDirty: number;
	/** utime + stime, seconds. */
	cpu: number;
	/** Page faults served without I/O: what an allocator that purges and re-touches pages pays. */
	minorFaults: number;
}

function procMem(pid: number): ProcMem {
	const status = readKb(`/proc/${pid}/status`);
	const smaps = readKb(`/proc/${pid}/smaps_rollup`);
	const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
	const fields = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
	return {
		vmRss: status.VmRSS,
		vmSwap: status.VmSwap,
		rssAnon: status.RssAnon,
		smapsRss: smaps.Rss,
		anonymous: smaps.Anonymous,
		privateDirty: smaps.Private_Dirty,
		cpu: (Number(fields[11]) + Number(fields[12])) / 100, // USER_HZ is 100 on Linux
		minorFaults: Number(fields[7]),
	};
}

function adminGet(socketPath: string, path: string): Promise<any> {
	return new Promise((resolvePromise, reject) => {
		const req = httpGet({ socketPath, path, timeout: 5000 }, (res) => {
			let body = '';
			res.setEncoding('utf8');
			res.on('error', reject);
			res.on('data', (chunk) => (body += chunk));
			res.on('end', () => {
				try {
					resolvePromise(JSON.parse(body));
				} catch (err) {
					reject(err);
				}
			});
		});
		req.on('timeout', () => req.destroy(new Error(`admin ${path} timed out`)));
		req.on('error', reject);
	});
}

interface Sample {
	label: string;
	t: number;
	/** symphony's active gauge (includes in-flight handshakes, of which a settled phase has none). */
	conns: number;
	halfClosed: number;
	proc: ProcMem;
	/** VmRSS change over the preceding 30 s of the timeline, bytes/s: the plateau check. */
	rssSlope30s?: number;
	cgroup?: CgroupMem;
	tcpMemGlobal: number;
	sockets?: SocketMem;
	clientSockets?: SocketMem;
	clients: ClientStats;
	upstreams: UpstreamStats;
}

interface TimelinePoint {
	t: number;
	phase: string;
	conns: number;
	vmRss: number;
	vmSwap: number;
	cpu: number;
	tcpMemGlobal: number;
	cgroupSock?: number;
}

// ── Orchestrator ──────────────────────────────────────────────────────────────

const sleep = (ms: number): Promise<void> => new Promise((r) => setTimeout(r, ms));

class RunAborted extends Error {}

class Child {
	readonly name: string;
	readonly proc: ChildProcess;
	private seq = 0;
	private readonly waiting = new Map<number, { resolve: (stats: any) => void; reject: (err: Error) => void }>();
	readonly ready: Promise<void>;
	exited?: string;

	constructor(name: string, proc: ChildProcess) {
		this.name = name;
		this.proc = proc;
		this.ready = new Promise((resolveReady, reject) => {
			const fail = (reason: string): void => {
				this.exited ??= reason;
				reject(new Error(this.exited));
				for (const waiter of [...this.waiting.values()]) waiter.reject(new RunAborted(this.exited));
			};
			proc.on('error', (err) => fail(`${name} failed: ${err.message}`));
			proc.once('exit', (code, signal) => fail(`${name} exited (${signal ?? code})`));
			const onMessage = (msg: any): void => {
				if (msg.type === 'ready') resolveReady();
				else if (msg.type === 'stats') this.waiting.get(msg.seq)?.resolve(msg.stats);
			};
			// A forked Node child talks over IPC; the python slow reader over stdin/stdout JSON lines.
			if (proc.stdout) {
				proc.stdin!.on('error', (err) => fail(`${name} stdin: ${err.message}`));
				createInterface({ input: proc.stdout }).on('line', (line) => {
					try {
						onMessage(JSON.parse(line));
					} catch {
						fail(`${name} wrote a malformed line: ${line.slice(0, 80)}`); // e.g. cut off as it died
					}
				});
			} else {
				proc.on('message', onMessage);
			}
		});
		this.ready.catch(() => {});
	}

	send(cmd: ClientCommand | UpstreamCommand): void {
		if (this.exited) throw new RunAborted(this.exited);
		if (this.proc.stdin) this.proc.stdin.write(JSON.stringify(cmd) + '\n');
		else this.proc.send(cmd);
	}

	stats<T>(): Promise<T> {
		const seq = ++this.seq;
		return new Promise((resolveStats, reject) => {
			const settle = (): void => {
				clearTimeout(timer);
				this.waiting.delete(seq);
			};
			const waiter = {
				resolve: (stats: T): void => {
					settle();
					resolveStats(stats);
				},
				reject: (err: Error): void => {
					settle();
					reject(err);
				},
			};
			const timer = setTimeout(
				() => waiter.reject(new RunAborted(`${this.name} did not answer within ${IPC_TIMEOUT_MS} ms`)),
				IPC_TIMEOUT_MS
			);
			this.waiting.set(seq, waiter);
			try {
				this.send({ type: 'stats', seq });
			} catch (err) {
				waiter.reject(err as Error);
			}
		});
	}
}

class Run {
	readonly samples: Sample[] = [];
	readonly timeline: TimelinePoint[] = [];
	phase = 'start';
	private readonly started = performance.now();
	private timer?: NodeJS.Timeout;
	private fault?: string;

	private readonly opts: Options;
	readonly pid: number;
	readonly port: number;
	readonly adminSocket: string;
	readonly cgroupDir: string | undefined;
	readonly clients: Child[];
	/** python3 clients that can stall with a small receive window; part of every target total. */
	readonly slowClients: Child[];
	readonly upstreams: Child[];

	constructor(
		opts: Options,
		pid: number,
		port: number,
		adminSocket: string,
		cgroupDir: string | undefined,
		clients: Child[],
		slowClients: Child[],
		upstreams: Child[]
	) {
		this.opts = opts;
		this.pid = pid;
		this.port = port;
		this.adminSocket = adminSocket;
		this.cgroupDir = cgroupDir;
		this.clients = clients;
		this.slowClients = slowClients;
		this.upstreams = upstreams;
	}

	startTimeline(): void {
		const ownCgroup = cgroupDirOf(process.pid);
		// TCP memory is host-wide: past tcp_mem[1] the kernel squeezes every socket on the box, not just
		// this benchmark's, so stop well short of it.
		const tcpPressure = pagesToBytes(Number(readFileSync('/proc/sys/net/ipv4/tcp_mem', 'utf8').trim().split(/\s+/)[1]));
		this.timer = setInterval(() => {
			const tcp = tcpMemBytes();
			if (tcp > tcpPressure * 0.8) {
				this.fault = `TCP memory ${(tcp / 1048576).toFixed(0)} MiB is near the host's tcp_mem pressure threshold`;
			}
			const available = (readKb('/proc/meminfo').MemAvailable ?? 0) / 1048576;
			const headroom = Math.min(
				cgroupHeadroomMb(ownCgroup),
				this.cgroupDir ? cgroupHeadroomMb(this.cgroupDir) : Infinity
			);
			if (Math.min(available, headroom) < this.opts.minAvailableMb) {
				this.fault = `memory low: MemAvailable ${available.toFixed(0)} MiB, cgroup headroom ${headroom.toFixed(0)} MiB`;
			}
			const dead = [...this.clients, ...this.slowClients, ...this.upstreams].find((c) => c.exited);
			if (dead) this.fault = dead.exited;
			this.symphonyConns()
				.then(({ conns }) => {
					if (this.timer === undefined) return; // answered after the run ended
					const mem = procMem(this.pid);
					this.timeline.push({
						t: performance.now() - this.started,
						phase: this.phase,
						conns,
						vmRss: mem.vmRss,
						vmSwap: mem.vmSwap,
						cpu: mem.cpu,
						tcpMemGlobal: tcp,
						cgroupSock: this.cgroupDir ? cgroupMem(this.cgroupDir).sock : undefined,
					});
				})
				.catch(() => {});
		}, 2000);
	}

	stopTimeline(): void {
		clearInterval(this.timer);
		this.timer = undefined;
	}

	async symphonyConns(): Promise<{ conns: number; halfClosed: number }> {
		const snap = await adminGet(this.adminSocket, '/metrics.json');
		let conns = 0;
		let halfClosed = 0;
		for (const proxy of snap.proxies) {
			conns += proxy.metrics.activeConnections;
			for (const l of proxy.metrics.listeners) halfClosed += l.halfClosedConnections;
		}
		return { conns, halfClosed };
	}

	/** Polls in 1 s steps so a fault aborts the run within a second. */
	async hold(ms: number): Promise<void> {
		const until = performance.now() + ms;
		while (performance.now() < until) {
			this.checkAlive();
			await sleep(Math.min(1000, until - performance.now()));
		}
		this.checkAlive();
	}

	private checkAlive(): void {
		if (this.fault) throw new RunAborted(this.fault);
		const dead = [...this.clients, ...this.slowClients, ...this.upstreams].find((c) => c.exited);
		if (dead) throw new RunAborted(dead.exited);
		if (!existsSync(`/proc/${this.pid}`)) throw new RunAborted('symphony exited');
	}

	broadcast(cmd: ClientCommand): void {
		for (const c of this.clients) c.send(cmd);
	}

	push(rate: number, stamp = false): void {
		for (const u of this.upstreams) u.send({ type: 'push', rate, size: this.opts.msgSize, stamp });
	}

	slow(cmd: ClientCommand): void {
		for (const c of this.slowClients) c.send(cmd);
	}

	/** Splits a total across client processes, the slow-reader share to the python clients. */
	setTarget(total: number): void {
		const slowTotal = this.slowClients.length ? Math.round(total * this.opts.slowFraction) : 0;
		const split = (children: Child[], n: number): void =>
			children.forEach((c, i) =>
				c.send({ type: 'target', live: Math.floor(n / children.length) + (i < n % children.length ? 1 : 0) })
			);
		split(this.slowClients, slowTotal);
		split(this.clients, total - slowTotal);
	}

	async clientTotals(): Promise<ClientStats> {
		const sum = emptyClientStats();
		const all = [...this.clients, ...this.slowClients];
		for (const s of await Promise.all(all.map((c) => c.stats<ClientStats>()))) {
			for (const k of Object.keys(emptyClientStats()) as (keyof ClientStats)[]) (sum[k] as number) += s[k] as number;
			if (s.latency) {
				sum.latency ??= new Array(LATENCY_BUCKETS).fill(0);
				s.latency.forEach((n, i) => (sum.latency![i] += n));
			}
		}
		return sum;
	}

	async upstreamTotals(): Promise<UpstreamStats> {
		const sum = emptyUpstreamStats();
		for (const s of await Promise.all(this.upstreams.map((c) => c.stats<UpstreamStats>()))) {
			for (const k of Object.keys(sum) as (keyof UpstreamStats)[]) sum[k] += s[k];
		}
		return sum;
	}

	/**
	 * Waits until the clients, symphony and the upstreams all hold `total` connections (±0.5%; churn
	 * keeps it moving). A client-side close is not reclamation: symphony and the upstream have to
	 * agree before a drop counts as done.
	 */
	async reach(total: number): Promise<void> {
		const tolerance = Math.max(5, total * 0.005);
		const rate = Math.min(this.opts.openRate, this.opts.closeRate) || 1;
		const deadline =
			performance.now() + 60_000 + (3 * Math.abs(total - (await this.clientTotals()).live) * 1000) / rate;
		for (;;) {
			const [clients, upstreams, { conns }] = await Promise.all([
				this.clientTotals(),
				this.upstreamTotals(),
				this.symphonyConns(),
			]);
			if ([clients.live, upstreams.conns, conns].every((n) => Math.abs(n - total) <= tolerance)) return;
			if (performance.now() > deadline) {
				throw new RunAborted(
					`stuck short of ${total}: clients ${clients.live} (${clients.failed} failed), symphony ${conns}, upstream ${upstreams.conns}`
				);
			}
			await this.hold(1000);
		}
	}

	/** Lets every queued byte arrive, then checks nothing was lost in either direction. */
	async drainAndVerify(): Promise<string | undefined> {
		this.push(0);
		for (const u of this.upstreams) u.send({ type: 'slow', rate: 0 });
		this.broadcast({ type: 'ping', intervalMs: 0, size: 0 });
		this.slow({ type: 'resume' });
		let last = -1;
		let stableFor = 0;
		const deadline = performance.now() + 120_000;
		for (;;) {
			const [clients, upstreams] = await Promise.all([this.clientTotals(), this.upstreamTotals()]);
			if (clients.lost > 0) return `${clients.lost} connections closed without the client closing them`;
			if (clients.bytesIn === upstreams.bytesOut && upstreams.bytesIn === clients.bytesOut) return undefined;
			stableFor = clients.bytesIn === last ? stableFor + 1 : 0;
			last = clients.bytesIn;
			if (stableFor >= 10 || performance.now() > deadline) {
				return (
					`payload mismatch: upstream wrote ${upstreams.bytesOut} B, clients read ${clients.bytesIn} B; ` +
					`clients wrote ${clients.bytesOut} B, upstream read ${upstreams.bytesIn} B ` +
					`(${clients.lost} connections lost, ${clients.failed} failed)`
				);
			}
			await this.hold(1000);
		}
	}

	async sample(label: string): Promise<Sample> {
		const [{ conns, halfClosed }, clients, upstreams] = await Promise.all([
			this.symphonyConns(),
			this.clientTotals(),
			this.upstreamTotals(),
		]);
		const proc = procMem(this.pid);
		const t = performance.now() - this.started;
		const before = this.timeline.find((p) => p.t >= t - 30_000);
		const sample: Sample = {
			label,
			t,
			conns,
			halfClosed,
			proc,
			rssSlope30s: before && t - before.t >= 10_000 ? ((proc.vmRss - before.vmRss) * 1000) / (t - before.t) : undefined,
			cgroup: this.cgroupDir ? cgroupMem(this.cgroupDir) : undefined,
			tcpMemGlobal: tcpMemBytes(),
			sockets: socketMem(this.port, 'sport'),
			clientSockets: socketMem(this.port, 'dport'),
			clients,
			upstreams,
		};
		this.samples.push(sample);
		// A fault raised while sampling (memory, TCP pressure, a dead child) invalidates even the last sample.
		this.checkAlive();
		const mb = (b: number): string => (b / 1048576).toFixed(0);
		const kernel = sample.sockets ? sample.sockets.rmem + sample.sockets.wqueued + sample.sockets.fwd : undefined;
		console.log(
			`    ${label.padEnd(12)} conns ${String(conns).padStart(7)}  rss ${mb(proc.vmRss)} MiB  swap ${mb(proc.vmSwap)} MiB` +
				(kernel === undefined ? '' : `  sock(sym) ${mb(kernel)} MiB`) +
				(sample.cgroup ? `  cg sock ${mb(sample.cgroup.sock)} MiB` : '') +
				`  tcp(all) ${mb(sample.tcpMemGlobal)} MiB  cpu ${proc.cpu.toFixed(0)} s`
		);
		return sample;
	}
}

interface RunResult {
	arm: string;
	kind: PhaseKind;
	repeat: number;
	error?: string;
	samples: Sample[];
	timeline: TimelinePoint[];
	trimMicros: number[];
	addonSha256?: string;
	/** The LD_PRELOAD allocator library, for the preload arms. */
	preloadSha256?: string;
	env?: Record<string, string>;
	maps?: string[];
	/** symphony's Cpus_allowed_list, to show --symphony-cpus took effect. */
	cpusAllowed?: string;
}

function generateCert(dir: string): { cert: string; key: string } {
	const cert = join(dir, 'cert.pem');
	const key = join(dir, 'key.pem');
	// ECDSA P-256: cheap handshakes, so ramping 100k connections is not CPU-bound on the clients.
	const res = spawnSync(
		'openssl',
		[
			'req',
			'-x509',
			'-newkey',
			'ec',
			'-pkeyopt',
			'ec_paramgen_curve:P-256',
			'-nodes',
			'-keyout',
			key,
			'-out',
			cert,
			'-days',
			'30',
			'-subj',
			`/CN=${SNI}`,
			'-addext',
			`subjectAltName=DNS:${SNI}`,
		],
		{ encoding: 'utf8' }
	);
	if (res.status !== 0) throw new Error(`openssl failed: ${res.error?.message ?? res.stderr}`);
	return { cert, key };
}

/** dist/ next to a different addon, so the default build in the repo root stays untouched. */
function stageAddon(addon: string, dir: string): { serverJs: string; addon: string } {
	mkdirSync(dir, { recursive: true, mode: 0o700 });
	cpSync(join(ROOT, 'dist'), join(dir, 'dist'), { recursive: true });
	copyFileSync(join(ROOT, 'package.json'), join(dir, 'package.json'));
	const staged = join(dir, `symphony.linux-${process.arch}-gnu.node`);
	copyFileSync(addon, staged);
	return { serverJs: join(dir, 'dist', 'server.js'), addon: staged };
}

function freePort(): Promise<number> {
	return new Promise((resolvePort, reject) => {
		const srv = createNetServer();
		srv.listen(0, '127.0.0.1', () => {
			const { port } = srv.address() as { port: number };
			srv.close(() => resolvePort(port));
		});
		srv.on('error', reject);
	});
}

function canUseScope(): boolean {
	return spawnSync('systemd-run', ['--user', '--scope', '--quiet', 'true'], { encoding: 'utf8' }).status === 0;
}

async function waitFor(check: () => Promise<boolean>, timeoutMs: number, what: string): Promise<void> {
	const deadline = performance.now() + timeoutMs;
	for (;;) {
		try {
			if (await check()) return;
		} catch (err) {
			if (err instanceof RunAborted) throw err; // anything else means not up yet
		}
		if (performance.now() > deadline) throw new Error(`timed out waiting for ${what}`);
		await sleep(200);
	}
}

const sha256 = (file: string): string => createHash('sha256').update(readFileSync(file)).digest('hex');

/** Everything a run started, so a signal or crash can stop it. */
const live = new Set<ChildProcess>();
const socketDirs = new Set<string>();

function removeSocketDir(dir: string): void {
	rmSync(dir, { recursive: true, force: true });
	socketDirs.delete(dir);
}
/** Set by a signal: a run still starting up must not leave a process the stop snapshot missed. */
let stopping = false;

async function stopAll(children: ChildProcess[]): Promise<void> {
	await Promise.all(
		children.map(async (child) => {
			if (child.exitCode !== null || child.signalCode !== null) return;
			const exited = new Promise((r) => child.once('exit', r));
			try {
				child.send({ type: 'exit' });
			} catch {
				child.kill('SIGTERM'); // no IPC channel (symphony, the python reader), or it closed under us
			}
			const term = setTimeout(() => child.kill('SIGTERM'), 5_000);
			const kill = setTimeout(() => child.kill('SIGKILL'), 15_000);
			await exited;
			clearTimeout(term);
			clearTimeout(kill);
		})
	);
	for (const child of children) live.delete(child);
}

async function runProcess(
	opts: Options,
	arm: Arm,
	kind: PhaseKind,
	repeat: number,
	useScope: boolean,
	cert: { cert: string; key: string }
): Promise<RunResult> {
	const runDir = join(opts.out, `${arm.name}-${kind}-r${repeat}`);
	mkdirSync(runDir, { recursive: true, mode: 0o700 });
	const port = await freePort();
	// Sockets live apart from the results, whose path can be too deep for a socket address.
	const socketDir = mkdtempSync(join(socketRoot(), 'smo-'));
	socketDirs.add(socketDir);
	const adminSocket = join(socketDir, 'admin.sock');
	const result: RunResult = { arm: arm.name, kind, repeat, samples: [], timeline: [], trimMicros: [] };

	const upstreamPaths = Array.from({ length: opts.upstreams }, (_, i) => join(socketDir, `up${i}.sock`));
	const proxy: Record<string, unknown> = {
		// Production shape (host-manager): no idle timeout, TLS termination, UDS upstreams with IP
		// affinity, PROXY v1, symphony's default buffer sizes unless overridden.
		listeners: [{ port, host: '127.0.0.1', idleTimeoutMs: 0 }],
		routes: [
			{
				sni: SNI,
				terminateTls: true,
				cert: { certChainFile: cert.cert, privateKeyFile: cert.key },
				sourceAddressHeader: opts.sourceHeader,
				upstreams: upstreamPaths.map((path) => ({ kind: 'uds', path, ipAffinity: opts.ipAffinity })),
			},
		],
		readBufferSize: opts.readBufferSize,
		clientReadBufferSize: opts.clientReadBufferSize,
		upstreamReadBufferSize: opts.upstreamReadBufferSize,
		workerThreads: opts.workerThreads,
		...arm.config,
	};
	const configPath = join(runDir, 'config.json');

	const started: ChildProcess[] = [];
	const track = (child: ChildProcess): ChildProcess => {
		started.push(child);
		live.add(child);
		if (stopping) child.kill('SIGKILL');
		return child;
	};
	try {
		writeFileSync(
			configPath,
			JSON.stringify({ version: 1, admin: { socketPath: adminSocket }, proxies: [proxy] }, null, 2),
			{ mode: 0o600 }
		);
		const upstreams = upstreamPaths.map(
			(path, i) =>
				new Child(
					`upstream ${i}`,
					track(
						fork(
							__filename,
							[
								'--role',
								'upstream',
								'--socket',
								path,
								'--source-header',
								opts.sourceHeader,
								'--burst',
								String(opts.burstSize),
							],
							{
								stdio: ['ignore', 'inherit', 'inherit', 'ipc'],
							}
						)
					)
				)
		);
		await Promise.all(upstreams.map((u) => u.ready));

		const staged = arm.addon ? stageAddon(arm.addon, join(runDir, 'stage')) : undefined;
		const serverJs = staged?.serverJs ?? join(ROOT, 'dist', 'server.js');
		const expectedAddon = staged?.addon ?? rootAddon();
		result.addonSha256 = sha256(expectedAddon);
		if (arm.mustMap) result.preloadSha256 = sha256(arm.mustMap);
		result.env = arm.env;
		// Only this arm's allocator variables reach symphony, whatever the orchestrator was started with.
		const env: Record<string, string> = { ...(process.env as Record<string, string>) };
		for (const name of [
			'LD_PRELOAD',
			'MALLOC_ARENA_MAX',
			'SYMPHONY_MALLOC_TRIM_INTERVAL_MS',
			'SYMPHONY_TLS_BUFFER_LIMIT',
			'RUST_LOG',
			'MALLOC_CONF',
			'_RJEM_MALLOC_CONF',
		]) {
			delete env[name];
		}
		const unit = `symphony-memory-oop-${process.pid}-${arm.name}-${kind}-r${repeat}`;
		const nodeCmd = [
			...(opts.symphonyCpus ? ['taskset', '-c', opts.symphonyCpus] : []),
			'env',
			...Object.entries(arm.env).map(([k, v]) => `${k}=${v}`),
			process.execPath,
			serverJs,
			'--config',
			configPath,
		];
		// MemorySwapMax=0 keeps symphony's anonymous memory in RAM, so VmRSS is its whole footprint; the
		// scope's own cgroup gives memory.stat sock/kernel, the numbers a production cgroup reader sees.
		const command = useScope
			? [
					'systemd-run',
					'--user',
					'--scope',
					'--quiet',
					'--collect',
					`--unit=${unit}`,
					'-p',
					'MemorySwapMax=0',
					'-p',
					'RuntimeMaxSec=7200',
					'--',
					...nodeCmd,
				]
			: nodeCmd;
		const log = createWriteStream(join(runDir, 'symphony.log'));
		await new Promise((resolveOpen, reject) => {
			log.once('open', resolveOpen);
			log.once('error', reject);
		});
		const symphony = track(spawn(command[0], command.slice(1), { env, stdio: ['ignore', log, log] }));
		let spawnError: Error | undefined;
		symphony.once('error', (err) => (spawnError = err));
		const pid = symphony.pid!;
		// systemd-run --scope, taskset and env all exec in place, so the spawned pid must be the server itself.
		await waitFor(
			async () => {
				if (spawnError) throw new RunAborted(`${command[0]}: ${spawnError.message}`);
				return (await adminGet(adminSocket, '/health')).pid === pid;
			},
			20_000,
			`symphony (pid ${pid}) on its admin socket`
		);
		const maps = readFileSync(`/proc/${pid}/maps`, 'utf8');
		result.maps = [
			...new Set(
				maps
					.split('\n')
					.map((l) => l.split(/\s+/)[5])
					.filter((p) => p && /\.so|\.node/.test(p))
			),
		];
		// maps records real paths; a symlinked library or output directory must still match.
		if (!maps.includes(realpathSync(expectedAddon))) throw new Error(`symphony did not load ${expectedAddon}`);
		if (arm.mustMap && !maps.includes(realpathSync(arm.mustMap))) {
			throw new Error(`${arm.mustMap} is not mapped into symphony`);
		}
		result.cpusAllowed = /^Cpus_allowed_list:\s*(\S+)/m.exec(readFileSync(`/proc/${pid}/status`, 'utf8'))?.[1];
		const cgroupDir = useScope ? cgroupDirOf(pid) : undefined;
		if (cgroupDir && !cgroupDir.endsWith(`/${unit}.scope`))
			throw new Error(`symphony landed in ${cgroupDir}, not its own scope`);
		// No memory.swap.max means the kernel does not account swap per cgroup; VmSwap still reports it.
		const swapMax = cgroupDir && join(cgroupDir, 'memory.swap.max');
		if (swapMax && existsSync(swapMax) && readFileSync(swapMax, 'utf8').trim() !== '0') {
			throw new Error(`${cgroupDir} still allows swap`);
		}

		const clients = Array.from(
			{ length: opts.clients },
			(_, id) =>
				new Child(
					`client ${id}`,
					track(
						fork(
							__filename,
							[
								'--role',
								'client',
								'--id',
								String(id),
								'--port',
								String(port),
								'--burst',
								String(opts.burstSize),
								'--max-inflight',
								String(opts.maxInflight),
							],
							{ stdio: ['ignore', 'inherit', 'inherit', 'ipc'] }
						)
					)
				)
		);
		const slowTotal = kind === 'abc' ? Math.round(opts.conns * opts.slowFraction) : 0;
		const slowClients = Array.from(
			{ length: Math.ceil(slowTotal / 5000) },
			(_, i) =>
				new Child(
					`slow client ${i}`,
					track(
						spawn(
							'python3',
							[
								'-c',
								SLOW_CLIENT_PY,
								'--port',
								String(port),
								'--net',
								String(SLOW_NET + i),
								'--sni',
								SNI,
								'--rcvbuf',
								String(opts.slowRcvbuf),
								'--mss',
								String(opts.slowMss),
								'--burst',
								String(opts.burstSize),
							],
							{ stdio: ['pipe', 'pipe', 'inherit'] }
						)
					)
				)
		);
		await Promise.all([...clients, ...slowClients].map((c) => c.ready));

		const run = new Run(opts, pid, port, adminSocket, cgroupDir, clients, slowClients, upstreams);
		result.samples = run.samples;
		result.timeline = run.timeline;
		run.startTimeline();
		const processes = opts.clients + slowClients.length;
		const rates: ClientCommand = { type: 'rates', open: opts.openRate / processes, close: opts.closeRate / processes };
		run.broadcast(rates);
		run.slow(rates);
		const startTraffic = (): void => {
			run.push(opts.msgRate);
			run.broadcast({ type: 'ping', intervalMs: opts.pingIntervalMs, size: opts.pingSize });
		};

		try {
			run.phase = 'idle';
			await run.hold(3000);
			await run.sample('idle');
			if (kind === 'abc') {
				run.phase = 'parked';
				const half = Math.round(opts.conns / 2);
				run.setTarget(half);
				await run.reach(half);
				await run.hold(opts.settleMs);
				await run.sample('parked-half');
				run.setTarget(opts.conns);
				await run.reach(opts.conns);
				await run.hold(opts.settleMs);
				await run.sample('parked');

				run.phase = 'active';
				startTraffic();
				await run.hold(opts.activeHoldMs);
				await run.sample('active');

				run.phase = 'slow';
				if (slowClients.length) {
					run.slow({ type: 'pause' });
					for (const u of upstreams) u.send({ type: 'slow', rate: opts.slowMsgRate });
					await run.hold(opts.slowHoldMs / 2);
					await run.sample('slow-mid');
					await run.hold(opts.slowHoldMs / 2);
					await run.sample('slow');
				}

				run.phase = 'drain';
				const mismatch = await run.drainAndVerify();
				await run.sample('drained');
				if (mismatch) throw new RunAborted(mismatch);
			} else if (kind === 'soak') {
				startTraffic();
				run.broadcast({ type: 'churn', turnoverS: opts.churnTurnoverS });
				const low = Math.round(opts.conns * opts.dropFraction);
				// What a process that never saw the peak holds at the trough population: the troughs' floor.
				run.phase = 'fresh-low';
				run.setTarget(low);
				await run.reach(low);
				await run.hold(opts.peakHoldMs);
				await run.sample('fresh-low');
				for (let cycle = 1; cycle <= opts.cycles; cycle++) {
					run.phase = `ramp${cycle}`;
					run.setTarget(opts.conns);
					await run.reach(opts.conns);
					run.phase = `peak${cycle}`;
					await run.hold(opts.peakHoldMs);
					await run.sample(`peak${cycle}`);
					run.phase = `trough${cycle}`;
					run.setTarget(low);
					await run.reach(low);
					await run.hold(10_000);
					await run.sample(`trough${cycle}-start`);
					await run.hold(Math.max(0, opts.troughHoldMs - 10_000));
					await run.sample(`trough${cycle}`);
				}
				// Without traffic or churn the allocator sees no activity, which is when lazy purging stalls.
				run.phase = 'quiet-low';
				run.broadcast({ type: 'churn', turnoverS: 0 });
				run.push(0);
				run.broadcast({ type: 'ping', intervalMs: 0, size: 0 });
				await run.hold(opts.settleMs);
				await run.sample('quiet-low-start');
				await run.hold(Math.max(0, opts.troughHoldMs - opts.settleMs));
				await run.sample('quiet-low');
				run.phase = 'zero';
				run.setTarget(0);
				await run.reach(0);
				await run.hold(opts.settleMs);
				await run.sample('zero-start');
				await run.hold(Math.max(0, opts.troughHoldMs - opts.settleMs));
				await run.sample('zero');
				const last = run.samples[run.samples.length - 1];
				if (last.clients.lost > 0) {
					throw new RunAborted(`${last.clients.lost} connections closed without the client closing them`);
				}
			} else if (kind === 'cpu') {
				run.phase = 'parked';
				run.broadcast({ type: 'latency', msgSize: opts.msgSize });
				run.setTarget(opts.conns);
				await run.reach(opts.conns);
				await run.hold(opts.settleMs);
				run.phase = 'warmup';
				run.push(opts.msgRate, true);
				await run.hold(opts.settleMs);
				await run.sample('cpu-0');
				for (let w = 1; w <= opts.cpuWindows; w++) {
					run.phase = `window${w}`;
					await run.hold(opts.cpuWindowMs);
					await run.sample(`cpu-${w}`);
				}
				run.phase = 'drain';
				const mismatch = await run.drainAndVerify();
				await run.sample('drained');
				if (mismatch) throw new RunAborted(mismatch);
			} else {
				run.phase = 'ramp';
				startTraffic();
				run.broadcast({ type: 'churn', turnoverS: opts.churnTurnoverS });
				run.setTarget(opts.conns);
				await run.reach(opts.conns);
				run.phase = 'peak';
				await run.hold(opts.peakHoldMs);
				await run.sample('peak');

				run.phase = 'drop';
				const low = Math.round(opts.conns * opts.dropFraction);
				run.setTarget(low);
				await run.reach(low);
				await run.hold(10_000);
				await run.sample('drop-start');
				await run.hold(Math.max(0, opts.dropHoldMs - 10_000));
				await run.sample('drop-end');

				run.phase = 'ramp2';
				run.setTarget(opts.conns);
				await run.reach(opts.conns);
				run.phase = 'peak2';
				await run.hold(opts.peakHoldMs);
				await run.sample('peak2');

				// Same connections with traffic and churn stopped: what is left is not active-traffic state.
				run.phase = 'quiesced';
				run.broadcast({ type: 'churn', turnoverS: 0 });
				run.push(0);
				run.broadcast({ type: 'ping', intervalMs: 0, size: 0 });
				await run.hold(opts.settleMs);
				const quiesced = await run.sample('quiesced');
				if (quiesced.clients.lost > 0) {
					throw new RunAborted(`${quiesced.clients.lost} connections closed without the client closing them`);
				}
			}
		} catch (err) {
			if (!(err instanceof RunAborted)) throw err;
			result.error = err.message;
			console.warn(`    run invalid: ${err.message}`);
		} finally {
			run.stopTimeline();
		}
	} catch (err) {
		result.error = (err as Error).message;
		console.warn(`    run failed: ${result.error}`);
	} finally {
		await stopAll(started);
		removeSocketDir(socketDir);
	}

	const logFile = join(runDir, 'symphony.log');
	if (existsSync(logFile)) {
		for (const m of readFileSync(logFile, 'utf8').matchAll(/malloc_trim elapsed_us=(\d+)/g))
			result.trimMicros.push(Number(m[1]));
	}
	writeFileSync(join(runDir, 'result.json'), JSON.stringify(result, null, 2));
	return result;
}

// ── Summary ───────────────────────────────────────────────────────────────────

/** Per-run derived figures, bytes per connection unless the name says otherwise. */
function derive(opts: Options, r: RunResult): Record<string, number> {
	const at = (label: string): Sample | undefined => r.samples.find((s) => s.label === label);
	const kernel = (s: Sample): number => (s.sockets ? s.sockets.rmem + s.sockets.wqueued + s.sockets.fwd : NaN);
	const maxSwap = Math.max(0, ...r.samples.map((s) => s.proc.vmSwap));
	const out: Record<string, number> = { maxSwapMiB: maxSwap / 1048576 };
	const idle = at('idle');
	if (r.kind === 'abc') {
		const half = at('parked-half');
		const parked = at('parked');
		const active = at('active');
		const slowMid = at('slow-mid');
		const slow = at('slow');
		if (parked && idle) {
			out.parkedTotal = parked.proc.vmRss / parked.conns;
			out.parkedOverIdle = (parked.proc.vmRss - idle.proc.vmRss) / parked.conns;
			out.parkedKernel = kernel(parked) / parked.conns;
		}
		if (parked && half) out.parkedMarginal = (parked.proc.vmRss - half.proc.vmRss) / (parked.conns - half.conns);
		if (active && parked) {
			const seconds = (active.t - parked.t) / 1000;
			out.activeTotal = active.proc.vmRss / active.conns;
			out.activeDelta = (active.proc.vmRss - parked.proc.vmRss) / active.conns;
			out.activeKernel = kernel(active) / active.conns;
			out.activeSlopeKiBs = (active.rssSlope30s ?? NaN) / 1024;
			out.activeCpuPct = ((active.proc.cpu - parked.proc.cpu) / seconds) * 100;
			// Delivered fan-out as a share of what was asked for: arms are only comparable at equal work.
			const delivered = active.clients.bytesIn - parked.clients.bytesIn;
			out.activeDeliveredPct = (delivered / (opts.msgRate * opts.msgSize * active.conns * seconds)) * 100;
		}
		if (slow && active && slow.clients.paused > 0) {
			out.slowConns = slow.clients.paused;
			out.slowDeltaPerSlow = (slow.proc.vmRss - active.proc.vmRss) / slow.clients.paused;
			out.slowKernelPerSlow = (kernel(slow) - kernel(active)) / slow.clients.paused;
			out.slowTcpMemGlobalMiB = slow.tcpMemGlobal / 1048576;
			if (slow.cgroup && active.cgroup)
				out.slowCgroupSockPerSlow = (slow.cgroup.sock - active.cgroup.sock) / slow.clients.paused;
			if (slowMid) out.slowSecondHalfPerSlow = (slow.proc.vmRss - slowMid.proc.vmRss) / slow.clients.paused;
		}
	} else if (r.kind === 'soak') {
		const footprint = (s: Sample): number => s.proc.vmRss + s.proc.vmSwap;
		let firstPeak: Sample | undefined;
		let maxPeak = 0;
		for (let c = 1; c <= opts.cycles; c++) {
			const peak = at(`peak${c}`);
			const troughStart = at(`trough${c}-start`);
			const trough = at(`trough${c}`);
			if (!peak) break;
			firstPeak ??= peak;
			maxPeak = Math.max(maxPeak, footprint(peak));
			out[`peak${c}MiB`] = footprint(peak) / 1048576;
			if (troughStart) out[`troughStart${c}Pct`] = (footprint(troughStart) / footprint(peak)) * 100;
			if (trough) {
				out[`trough${c}MiB`] = footprint(trough) / 1048576;
				out[`trough${c}Pct`] = (footprint(trough) / footprint(peak)) * 100;
				out[`trough${c}PctOfMaxPeak`] = (footprint(trough) / maxPeak) * 100;
			}
		}
		const lastPeak = at(`peak${opts.cycles}`);
		const firstTrough = at('trough1');
		const lastTrough = at(`trough${opts.cycles}`);
		if (firstPeak) out.peak1PerConn = footprint(firstPeak) / firstPeak.conns;
		const freshLow = at('fresh-low');
		if (freshLow) {
			out.freshLowMiB = footprint(freshLow) / 1048576;
			for (let c = 1; c <= opts.cycles; c++) {
				const trough = at(`trough${c}`);
				if (trough) out[`trough${c}OverFreshMiB`] = (footprint(trough) - footprint(freshLow)) / 1048576;
			}
		}
		for (const label of ['quiet-low-start', 'quiet-low', 'zero-start', 'zero']) {
			const s = at(label);
			if (s) out[`${label}MiB`] = footprint(s) / 1048576;
		}
		if (idle) out.idleMiB = footprint(idle) / 1048576;
		if (firstPeak && lastPeak) out.peakGrowthMiB = (footprint(lastPeak) - footprint(firstPeak)) / 1048576;
		if (firstTrough && lastTrough) out.troughGrowthMiB = (footprint(lastTrough) - footprint(firstTrough)) / 1048576;
	} else if (r.kind === 'cpu') {
		const first = at('cpu-0');
		const last = at(`cpu-${opts.cpuWindows}`);
		if (first && last) {
			const seconds = (last.t - first.t) / 1000;
			const cpu = last.proc.cpu - first.proc.cpu;
			const fanOut = last.clients.bytesIn - first.clients.bytesIn;
			const proxied = fanOut + (last.upstreams.bytesIn - first.upstreams.bytesIn);
			const messages = fanOut / opts.msgSize;
			out.cpuMsgsPerS = messages / seconds;
			out.cpuDeliveredPct = (messages / (opts.msgRate * last.conns * seconds)) * 100;
			out.cpuCores = cpu / seconds;
			out.cpuSecPerGB = cpu / (proxied / 1e9);
			out.cpuSecPerMMsgs = cpu / (messages / 1e6);
			out.minorFaultsPerS = (last.proc.minorFaults - first.proc.minorFaults) / seconds;
			if (first.clients.latency && last.clients.latency) {
				const window = last.clients.latency.map((n, i) => n - first.clients.latency![i]);
				out.latencyP50Ms = percentileMicros(window, 0.5) / 1000;
				out.latencyP99Ms = percentileMicros(window, 0.99) / 1000;
				out.latencyP999Ms = percentileMicros(window, 0.999) / 1000;
			}
		}
	} else {
		const peak = at('peak');
		const dropStart = at('drop-start');
		const dropEnd = at('drop-end');
		const peak2 = at('peak2');
		const quiesced = at('quiesced');
		if (peak) {
			out.peakTotal = peak.proc.vmRss / peak.conns;
			out.peakKernel = kernel(peak) / peak.conns;
			if (peak.cgroup) out.peakCgroupSock = peak.cgroup.sock / peak.conns;
		}
		if (peak && dropStart) out.dropStartRssPct = (dropStart.proc.vmRss / peak.proc.vmRss) * 100;
		if (peak && dropEnd) {
			out.dropEndRssPct = (dropEnd.proc.vmRss / peak.proc.vmRss) * 100;
			out.dropEndPerConn = dropEnd.proc.vmRss / dropEnd.conns;
			out.dropEndConnsPct = (dropEnd.conns / peak.conns) * 100;
			if (idle) out.retainedPct = ((dropEnd.proc.vmRss - idle.proc.vmRss) / (peak.proc.vmRss - idle.proc.vmRss)) * 100;
		}
		if (peak && peak2) {
			out.peak2Total = peak2.proc.vmRss / peak2.conns;
			out.peak2GrowthPerConn = (peak2.proc.vmRss - peak.proc.vmRss) / peak.conns;
		}
		if (peak2 && quiesced) out.quiescedDelta = (quiesced.proc.vmRss - peak2.proc.vmRss) / quiesced.conns;
	}
	if (r.trimMicros.length) {
		const sorted = [...r.trimMicros].sort((a, b) => a - b);
		out.trimP50Ms = sorted[Math.floor(sorted.length / 2)] / 1000;
		out.trimMaxMs = sorted[sorted.length - 1] / 1000;
	}
	return out;
}

function fmt(values: number[], digits = 0): string {
	const finite = values.filter((v) => v !== undefined && Number.isFinite(v));
	if (finite.length === 0) return '–';
	const mean = finite.reduce((a, b) => a + b, 0) / finite.length;
	const f = (v: number): string =>
		v.toLocaleString('en-US', { maximumFractionDigits: digits, minimumFractionDigits: digits });
	return finite.length === 1 ? f(mean) : `${f(mean)} (${f(Math.min(...finite))}–${f(Math.max(...finite))})`;
}

function summarize(opts: Options, results: RunResult[]): string {
	const groups = new Map<string, Record<string, number>[]>();
	for (const r of results) {
		if (r.error) continue;
		const key = `${r.arm}|${r.kind}`;
		groups.set(key, [...(groups.get(key) ?? []), derive(opts, r)]);
	}
	const cells = (rows: Record<string, number>[], spec: [string, number?][]): string =>
		spec
			.map(([key, digits]) =>
				fmt(
					rows.map((r) => r[key]),
					digits ?? 0
				)
			)
			.join(' | ');
	const table = (kind: string, header: string[], spec: [string, number?][]): string[] => [
		`| arm | runs | ${header.join(' | ')} |`,
		`|---|---|${header.map(() => '---').join('|')}|`,
		...[...groups]
			.filter(([key]) => key.endsWith(`|${kind}`))
			.map(([key, rows]) => `| ${key.split('|')[0]} | ${rows.length} | ${cells(rows, spec)} |`),
	];
	const lines = [
		`N=${opts.conns}, ${opts.clients} client procs, ${opts.upstreams} UDS upstreams (ipAffinity ${opts.ipAffinity}), ` +
			`msg ${opts.msgSize} B at ${opts.msgRate}/s/conn, ping ${opts.pingSize} B every ${opts.pingIntervalMs / 1000} s, ` +
			`slow fraction ${opts.slowFraction}, churn turnover ${opts.churnTurnoverS} s, drop to ${opts.dropFraction * 100}% ` +
			`held ${opts.dropHoldMs / 1000} s. Cells: mean (min–max) over runs; bytes per connection unless noted. ` +
			`RSS = VmRSS; kernel = symphony-side TCP skmem r+w+f from ss.`,
		'',
		'Parked → active → slow:',
		'',
		...table(
			'abc',
			[
				'parked total',
				'parked marginal',
				'parked over idle',
				'active total',
				'active Δ over parked',
				'active RSS slope KiB/s',
				'delivered % of target',
				'symphony CPU % (active)',
				'slow Δ per slow conn',
				'slow 2nd-half Δ per slow conn',
				'kernel/conn parked',
				'kernel/conn active',
				'kernel per slow conn',
				'cgroup sock per slow conn',
				'global TCP mem in slow MiB',
				'max VmSwap MiB',
			],
			[
				['parkedTotal'],
				['parkedMarginal'],
				['parkedOverIdle'],
				['activeTotal'],
				['activeDelta'],
				['activeSlopeKiBs', 1],
				['activeDeliveredPct', 1],
				['activeCpuPct', 0],
				['slowDeltaPerSlow'],
				['slowSecondHalfPerSlow'],
				['parkedKernel'],
				['activeKernel'],
				['slowKernelPerSlow'],
				['slowCgroupSockPerSlow'],
				['slowTcpMemGlobalMiB'],
				['maxSwapMiB'],
			]
		),
		'',
		'Churn → peak → drop → second peak → quiesced:',
		'',
		...table(
			'd',
			[
				'peak total',
				'drop-start RSS % of peak',
				'drop-end RSS % of peak',
				'drop-end conns % of peak',
				'retained over idle %',
				'drop-end per conn',
				'second peak total',
				'second-peak growth per peak conn',
				'quiesced Δ',
				'kernel/conn at peak',
				'cgroup sock/conn at peak',
				'malloc_trim p50 ms',
				'malloc_trim max ms',
				'max VmSwap MiB',
			],
			[
				['peakTotal'],
				['dropStartRssPct', 1],
				['dropEndRssPct', 1],
				['dropEndConnsPct', 1],
				['retainedPct', 1],
				['dropEndPerConn'],
				['peak2Total'],
				['peak2GrowthPerConn'],
				['quiescedDelta'],
				['peakKernel'],
				['peakCgroupSock'],
				['trimP50Ms', 1],
				['trimMaxMs', 1],
				['maxSwapMiB'],
			]
		),
	];
	const cycles = Array.from({ length: opts.cycles }, (_, i) => i + 1);
	if (groups.size && [...groups.keys()].some((key) => key.endsWith('|soak'))) {
		lines.push(
			'',
			`Soak, ${opts.cycles} cycles of ramp to ${opts.conns} under churn → hold ${opts.peakHoldMs / 1000} s → ` +
				`drop to ${opts.dropFraction * 100}% → hold ${opts.troughHoldMs / 1000} s. Footprint = VmRSS + VmSwap, MiB:`,
			'',
			...table(
				'soak',
				[
					'peak/conn c1 (B)',
					...cycles.map((c) => `peak c${c}`),
					...cycles.map((c) => `trough c${c}`),
					...cycles.map((c) => `trough c${c} % of peak`),
					'trough c1 +10 s % of peak',
					'peak growth c1→last',
					'trough growth c1→last',
				],
				[
					['peak1PerConn'],
					...cycles.map((c): [string, number] => [`peak${c}MiB`, 0]),
					...cycles.map((c): [string, number] => [`trough${c}MiB`, 0]),
					...cycles.map((c): [string, number] => [`trough${c}Pct`, 1]),
					['troughStart1Pct', 1],
					['peakGrowthMiB', 0],
					['troughGrowthMiB', 0],
				]
			),
			'',
			'Soak floors, MiB: fresh-low = a process that never saw the peak, at the trough population, before cycle 1; ' +
				'quiet = trough population with traffic and churn stopped; zero = every connection closed (start = +settle, end = +trough hold):',
			'',
			...table(
				'soak',
				[
					'idle',
					'fresh-low',
					...cycles.map((c) => `trough c${c} over fresh-low`),
					'quiet start',
					'quiet end',
					'zero start',
					'zero end',
				],
				[
					['idleMiB', 0],
					['freshLowMiB', 0],
					...cycles.map((c): [string, number] => [`trough${c}OverFreshMiB`, 0]),
					['quiet-low-startMiB', 0],
					['quiet-lowMiB', 0],
					['zero-startMiB', 0],
					['zeroMiB', 0],
				]
			)
		);
	}
	if ([...groups.keys()].some((key) => key.endsWith('|cpu'))) {
		lines.push(
			'',
			`Fan-out CPU, ${opts.conns} connections, ${opts.msgSize} B at ${opts.msgRate}/s/conn, ` +
				`${opts.cpuWindows} × ${opts.cpuWindowMs / 1000} s` +
				(opts.symphonyCpus ? `, symphony pinned to CPUs ${opts.symphonyCpus}` : '') +
				'. GB = payload bytes through symphony, both directions; latency = upstream write → client read:',
			'',
			...table(
				'cpu',
				[
					'msgs/s',
					'delivered %',
					'symphony cores',
					'CPU s per GB',
					'CPU s per 1M msgs',
					'minor faults/s',
					'p50 ms',
					'p99 ms',
					'p99.9 ms',
				],
				[
					['cpuMsgsPerS'],
					['cpuDeliveredPct', 1],
					['cpuCores', 3],
					['cpuSecPerGB', 2],
					['cpuSecPerMMsgs', 3],
					['minorFaultsPerS', 0],
					['latencyP50Ms', 2],
					['latencyP99Ms', 2],
					['latencyP999Ms', 2],
				]
			)
		);
	}
	const failed = results.filter((r) => r.error);
	if (failed.length)
		lines.push('', 'Invalid runs (excluded):', ...failed.map((r) => `- ${r.arm} ${r.kind} r${r.repeat}: ${r.error}`));
	return lines.join('\n');
}

function environment(): Record<string, string> {
	const run = (cmd: string, args: string[]): string => spawnSync(cmd, args, { encoding: 'utf8' }).stdout?.trim() ?? '';
	return {
		node: process.version,
		kernel: run('uname', ['-r']),
		glibc: (process.report.getReport() as any).header.glibcVersionRuntime ?? 'none',
		commit: run('git', ['-C', ROOT, 'rev-parse', 'HEAD']),
		harness: sha256(__filename),
		dirty: run('git', ['-C', ROOT, 'status', '--porcelain']) ? 'yes' : 'no',
		cpus: run('nproc', []),
		tcpMem: readFileSync('/proc/sys/net/ipv4/tcp_mem', 'utf8').trim(),
		tcpWmem: readFileSync('/proc/sys/net/ipv4/tcp_wmem', 'utf8').trim(),
		tcpRmem: readFileSync('/proc/sys/net/ipv4/tcp_rmem', 'utf8').trim(),
	};
}

function checkReleaseAddons(arms: Arm[]): void {
	if (!existsSync(join(ROOT, 'dist', 'server.js'))) {
		throw new Error('dist/server.js is missing: run `npm run build` (release) first');
	}
	for (const addon of new Set(arms.map((arm) => arm.addon ?? rootAddon()))) {
		if (!existsSync(addon)) throw new Error(`${addon} is missing: run \`npm run build\` (release) first`);
		// The release profile strips symbols; a debug build keeps them and would skew every number.
		const res = spawnSync('file', ['-L', addon], { encoding: 'utf8' });
		if (res.status === 0 && /not stripped/.test(res.stdout)) {
			throw new Error(`${addon} is a debug (unstripped) build: benchmark release builds only`);
		}
	}
}

function shuffle<T>(items: T[]): T[] {
	const out = [...items];
	for (let i = out.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		[out[i], out[j]] = [out[j], out[i]];
	}
	return out;
}

/** Repeats run as separate invocations (so a shared benchmark lock is not held for hours) pool here. */
function summarizeDirs(dirs: string[]): void {
	if (dirs.length === 0) throw new Error('--summarize needs at least one output directory');
	const runs = dirs.map((dir) => ({
		options: (JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8')) as { options: Options }).options,
		results: JSON.parse(readFileSync(join(dir, 'results.json'), 'utf8')) as RunResult[],
	}));
	// Build paths are not workload: the per-arm addon hash below is what identifies a build.
	const workload = (o: Options): string =>
		JSON.stringify({
			...o,
			arms: undefined,
			repeats: undefined,
			out: undefined,
			addonArms: undefined,
			armEnv: undefined,
			rustJemallocAddon: undefined,
			systemAddon: undefined,
			jemalloc: undefined,
			mimalloc: undefined,
			phases: undefined,
			fixedOrder: undefined,
			minAvailableMb: undefined,
		});
	for (const run of runs.slice(1)) {
		if (workload(run.options) !== workload(runs[0].options)) {
			throw new Error('--summarize: the directories were run with different workload options');
		}
	}
	const results = runs.flatMap((run) => run.results);
	const harnesses = new Set(
		dirs.map((dir) => JSON.parse(readFileSync(join(dir, 'meta.json'), 'utf8')).environment?.harness)
	);
	if (harnesses.size > 1) {
		console.warn(`--summarize: pooling ${harnesses.size} harness versions; check they measure the same way`);
	}
	// An arm name pools runs only when they ran the same native build, preloaded allocator and environment.
	const builds = new Map<string, string>();
	for (const r of results) {
		if (r.error) continue;
		const build = `${r.addonSha256}+${r.preloadSha256 ?? ''}+${JSON.stringify(Object.entries(r.env ?? {}).sort())}`;
		if (builds.has(r.arm) && builds.get(r.arm) !== build) {
			throw new Error(`--summarize: arm '${r.arm}' ran different builds across the directories`);
		}
		builds.set(r.arm, build);
	}
	console.log(summarize({ ...runs[0].options, repeats: runs.reduce((n, run) => n + run.options.repeats, 0) }, results));
}

/** Short and private: $XDG_RUNTIME_DIR is per-user tmpfs, unlike a benchmark runner's long TMPDIR. */
function socketRoot(): string {
	return process.env.XDG_RUNTIME_DIR || tmpdir();
}

async function orchestrate(argv: string[]): Promise<void> {
	const opts = parseOptions(argv);
	opts.out = join(opts.out, new Date().toISOString().replace(/[:.]/g, '-'));
	mkdirSync(opts.out, { recursive: true, mode: 0o700 });
	const cert = generateCert(opts.out);
	const useScope = opts.cgroup && canUseScope();
	if (opts.cgroup && !useScope)
		console.warn('systemd-run --user --scope unavailable: no cgroup stats, and symphony may swap');
	const arms = opts.arms.map((name) => resolveArm(name, opts));
	checkReleaseAddons(arms);
	// sun_path holds 108 bytes, and the admin server first binds a `.<pid>` sibling (≤ 8 more).
	const longest = join(socketRoot(), 'smo-XXXXXX', 'admin.sock');
	if (Buffer.byteLength(longest) + 8 > 107) {
		throw new Error(`${longest} is too long for a Unix socket path; set XDG_RUNTIME_DIR or TMPDIR shorter`);
	}
	const meta = { options: opts, environment: environment(), cgroup: useScope };
	writeFileSync(join(opts.out, 'meta.json'), JSON.stringify(meta, null, 2));
	console.log(`symphony memory-oop → ${opts.out}\n${JSON.stringify(meta)}`);

	const stopOnSignal = (signal: NodeJS.Signals): void => {
		stopping = true;
		console.warn(`${signal}: stopping ${live.size} child processes`);
		stopAll([...live]).finally(() => {
			for (const dir of [...socketDirs]) removeSocketDir(dir);
			process.exit(130);
		});
	};
	process.once('SIGINT', stopOnSignal);
	process.once('SIGTERM', stopOnSignal);

	const results: RunResult[] = [];
	for (let repeat = 1; repeat <= opts.repeats; repeat++) {
		// Shuffled per repeat, so drift on a shared host spreads across arms instead of biasing one.
		for (const arm of opts.fixedOrder ? arms : shuffle(arms)) {
			for (const kind of arm.phases) {
				if (stopping) return;
				console.log(`[${new Date().toISOString()}] ${arm.name} ${kind} repeat ${repeat}`);
				results.push(await runProcess(opts, arm, kind, repeat, useScope, cert));
				writeFileSync(join(opts.out, 'results.json'), JSON.stringify(results, null, 2));
			}
		}
	}
	const summary = summarize(opts, results);
	writeFileSync(join(opts.out, 'summary.md'), summary + '\n');
	console.log('\n' + summary);
}

// ── Entry ─────────────────────────────────────────────────────────────────────

const argv = process.argv.slice(2);
switch (argValue(argv, '--role')) {
	case 'client':
		runClient(argv);
		break;
	case 'upstream':
		runUpstream(argv);
		break;
	default:
		if (argv.includes('--summarize')) {
			summarizeDirs(argv.slice(argv.indexOf('--summarize') + 1));
			break;
		}
		orchestrate(argv).catch((err) => {
			console.error(err);
			stopAll([...live]).finally(() => process.exit(1));
		});
}
