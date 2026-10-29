//! CPU utilisation of the worker thread behind each monitored UDS slot, and the smoothed load of a
//! balancer's slots.
//!
//! A slot's configured `pid`/`tid` come from the upstream and may be in another PID namespace: Harper
//! in a container reports `process.pid` and `gettid()` as the container sees them, while symphony
//! reads the host's `/proc`. So a slot is first *discovered*: a connect-and-close to its socket reads
//! the owner's host pid (`SO_PEERCRED`, which the kernel translates into the reader's namespace),
//! and the `NSpid:` lines under `/proc/<host pid>` map the configured ids to host ids. Only a
//! discovered identity counts toward load; one that cannot be tied to the socket's owner is still
//! read as configured, for the balancer tiebreak alone.

use crate::protection::now_ns;
use crate::router::LiveRouteTable;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;
use tokio::sync::broadcast;

const SAMPLE_INTERVAL: Duration = Duration::from_millis(250);
/// How long one sample vouches for a thread's load.
const SAMPLE_VALID_NS: u64 = 1_000_000_000;
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(1);
const DISCOVERY_RETRY_NS: u64 = 5_000_000_000;
/// A resolved slot's owner is checked again this often: another process can take over the socket
/// path while the old thread is still alive, without the configuration changing.
const OWNER_RECHECK_NS: u64 = 30_000_000_000;
const MAX_CONCURRENT_DISCOVERIES: usize = 64;
const LOAD_TIME_CONSTANT_NS: f64 = 3_000_000_000.0;

/// Cached value of sysconf(_SC_CLK_TCK) — usually 100 on Linux.
fn clk_tck_hz() -> u64 {
	static CLK_TCK: OnceLock<u64> = OnceLock::new();
	*CLK_TCK.get_or_init(|| {
		let v = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
		if v > 0 {
			v as u64
		} else {
			100
		}
	})
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TaskStat {
	/// utime + stime.
	ticks: u64,
	/// Start time after boot, in clock ticks. Distinguishes a reused id from the thread it named.
	start: u64,
}

fn parse_task_stat(content: &str) -> Option<TaskStat> {
	// The comm field is parenthesised and may itself contain ')' — the last one ends it.
	let after_comm = content[content.rfind(')')? + 1..].trim_start();
	let fields: Vec<&str> = after_comm.split_whitespace().collect();
	// After comm: state(0) … utime(11) stime(12) … starttime(19).
	let utime: u64 = fields.get(11)?.parse().ok()?;
	let stime: u64 = fields.get(12)?.parse().ok()?;
	let start: u64 = fields.get(19)?.parse().ok()?;
	Some(TaskStat {
		ticks: utime + stime,
		start,
	})
}

/// The `NSpid:` ids, outermost (the namespace this procfs shows) first, innermost last.
fn parse_nspid(status: &str) -> Option<Vec<u32>> {
	let line = status.lines().find(|l| l.starts_with("NSpid:"))?;
	let ids: Option<Vec<u32>> = line["NSpid:".len()..]
		.split_whitespace()
		.map(|id| id.parse().ok())
		.collect();
	ids.filter(|ids| !ids.is_empty())
}

#[derive(Clone)]
struct ProcFs {
	root: PathBuf,
}

impl ProcFs {
	fn host() -> Self {
		Self {
			root: PathBuf::from("/proc"),
		}
	}

	fn task_stat(&self, pid: u32, tid: u32) -> Option<TaskStat> {
		let path = self.root.join(format!("{pid}/task/{tid}/stat"));
		parse_task_stat(&std::fs::read_to_string(path).ok()?)
	}

	fn nspid(&self, path: &Path) -> Option<Vec<u32>> {
		parse_nspid(&std::fs::read_to_string(path).ok()?)
	}

	/// The process's innermost pid and a map from each thread's innermost tid to its id here.
	fn process_view(&self, host_pid: u32) -> Option<ProcessView> {
		let innermost_pid = *self
			.nspid(&self.root.join(format!("{host_pid}/status")))?
			.last()?;
		let mut threads = HashMap::new();
		for entry in std::fs::read_dir(self.root.join(format!("{host_pid}/task"))).ok()? {
			let Ok(entry) = entry else { continue };
			if let Some(ids) = self.nspid(&entry.path().join("status")) {
				if let (Some(host), Some(inner)) = (ids.first(), ids.last()) {
					threads.insert(*inner, *host);
				}
			}
		}
		Some(ProcessView {
			innermost_pid,
			threads,
		})
	}
}

struct ProcessView {
	innermost_pid: u32,
	threads: HashMap<u32, u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Identity {
	Unresolved,
	/// Host ids of the thread, tied to the socket's owner. `start` detects id reuse.
	Discovered {
		pid: u32,
		tid: u32,
		start: u64,
	},
	/// The configured ids did not name the socket's owner; read as configured, never counted as load.
	Literal,
}

/// Decide what the configured ids name, given the socket owner's host pid. `Unresolved` (retry
/// soon) when the owner has exited or its thread is not there yet, as around a restart; `Literal`
/// only when a live owner's pid is not the configured one in any namespace.
fn resolve(
	configured_pid: u32,
	configured_tid: u32,
	owner: u32,
	proc: &ProcFs,
	views: &mut HashMap<u32, Option<ProcessView>>,
) -> Identity {
	let Some(view) = views
		.entry(owner)
		.or_insert_with(|| proc.process_view(owner))
	else {
		return Identity::Unresolved;
	};
	let host_tid = if owner == configured_pid {
		configured_tid
	} else if view.innermost_pid == configured_pid {
		match view.threads.get(&configured_tid) {
			Some(tid) => *tid,
			None => return Identity::Unresolved,
		}
	} else {
		return Identity::Literal;
	};
	match proc.task_stat(owner, host_tid) {
		Some(stat) => Identity::Discovered {
			pid: owner,
			tid: host_tid,
			start: stat.start,
		},
		None => Identity::Unresolved,
	}
}

struct SampleState {
	identity: Identity,
	next_discovery_ns: u64,
	/// A discovery's result (`None` = the connect failed), applied by the next sampling pass.
	discovered: Option<Option<u32>>,
	last_ticks: u64,
	/// Monotonic ns of the last successful read; 0 = no baseline.
	last_ns: u64,
	/// End of the window in which the latest discovered-identity sample counts as load; 0 = none.
	valid_until_ns: u64,
	util_permille: u32,
}

/// One slot's configured worker thread. Shared across route-table rebuilds while the slot's path
/// and configured ids are unchanged, so discovery and the sample baseline survive a reload.
pub struct ThreadCpu {
	path: Arc<str>,
	pid: u32,
	tid: u32,
	/// Last measured utilisation, read by `UdsBalancer::pick` as a tiebreak. 0 when unknown.
	util_permille: AtomicU32,
	/// Written by the sampling task (and a discovery's result).
	state: Mutex<SampleState>,
}

impl ThreadCpu {
	pub fn new(path: Arc<str>, pid: u32, tid: u32) -> Self {
		// Without Linux's /proc there is nothing to discover; keep reading as configured (a no-op).
		let identity = if cfg!(target_os = "linux") {
			Identity::Unresolved
		} else {
			Identity::Literal
		};
		Self {
			path,
			pid,
			tid,
			util_permille: AtomicU32::new(0),
			state: Mutex::new(SampleState {
				identity,
				next_discovery_ns: 0,
				discovered: None,
				last_ticks: 0,
				last_ns: 0,
				valid_until_ns: 0,
				util_permille: 0,
			}),
		}
	}

	pub fn configured(&self) -> (&str, u32, u32) {
		(&self.path, self.pid, self.tid)
	}

	pub fn util_permille(&self) -> u32 {
		self.util_permille.load(Ordering::Relaxed)
	}

	fn lock(&self) -> std::sync::MutexGuard<'_, SampleState> {
		self.state.lock().unwrap_or_else(|e| e.into_inner())
	}

	/// Claims a due discovery. Until its result is applied the next one is a retry interval away, so
	/// a discovery that never finishes (aborted at shutdown) is simply tried again.
	fn begin_discovery(&self, now: u64) -> bool {
		let mut state = self.lock();
		if !cfg!(target_os = "linux") || now < state.next_discovery_ns {
			return false;
		}
		state.next_discovery_ns = now.saturating_add(DISCOVERY_RETRY_NS);
		true
	}

	fn finish_discovery(&self, owner: Option<u32>) {
		self.lock().discovered = Some(owner);
	}

	#[cfg(test)]
	fn discovery_due(&self, now: u64) -> bool {
		now >= self.lock().next_discovery_ns
	}

	fn apply_discovery(
		&self,
		owner: Option<u32>,
		now: u64,
		proc: &ProcFs,
		views: &mut HashMap<u32, Option<ProcessView>>,
	) {
		let mut state = self.lock();
		let identity = match owner {
			Some(owner) => resolve(self.pid, self.tid, owner, proc, views),
			None => Identity::Unresolved,
		};
		state.next_discovery_ns = now.saturating_add(match identity {
			Identity::Unresolved => DISCOVERY_RETRY_NS,
			Identity::Discovered { .. } | Identity::Literal => OWNER_RECHECK_NS,
		});
		if identity != state.identity {
			state.identity = identity;
			state.last_ns = 0;
			state.valid_until_ns = 0;
		}
	}

	/// `views` caches process scans for this pass, shared by every slot of a process.
	fn sample(&self, now: u64, proc: &ProcFs, views: &mut HashMap<u32, Option<ProcessView>>) {
		let mut state = self.lock();
		if let Some(owner) = state.discovered.take() {
			drop(state);
			self.apply_discovery(owner, now, proc, views);
			state = self.lock();
		}
		// A pass that started before a newer one (after a stop and restart) changes nothing.
		if now <= state.last_ns {
			return;
		}
		let (pid, tid, start) = match state.identity {
			Identity::Discovered { pid, tid, start } => (pid, tid, Some(start)),
			Identity::Literal => (self.pid, self.tid, None),
			Identity::Unresolved => {
				state.util_permille = 0;
				self.util_permille.store(0, Ordering::Relaxed);
				return;
			}
		};
		let stat = proc
			.task_stat(pid, tid)
			.filter(|stat| start.is_none_or(|start| start == stat.start));
		let Some(stat) = stat else {
			// Never keep a value for a thread that can no longer be read: it may be gone, or its id
			// may now name another thread.
			state.last_ns = 0;
			state.valid_until_ns = 0;
			state.util_permille = 0;
			self.util_permille.store(0, Ordering::Relaxed);
			if start.is_some() {
				state.identity = Identity::Unresolved;
				state.next_discovery_ns = now;
			}
			return;
		};
		if state.last_ns > 0 {
			let delta_ticks = stat.ticks.saturating_sub(state.last_ticks) as f64;
			let delta_secs = (now - state.last_ns) as f64 / 1e9;
			let util =
				(delta_ticks / (delta_secs * clk_tck_hz() as f64) * 1000.0).min(1000.0) as u32;
			state.util_permille = util;
			self.util_permille.store(util, Ordering::Relaxed);
			if start.is_some() {
				state.valid_until_ns = now + SAMPLE_VALID_NS;
			}
		}
		state.last_ticks = stat.ticks;
		state.last_ns = now;
	}

	/// The latest sample of a discovered identity, while it is still fresh.
	fn load_sample(&self, now: u64) -> Option<u32> {
		let state = self.lock();
		(now < state.valid_until_ns).then_some(state.util_permille)
	}
}

/// Smoothed mean utilisation of a balancer's discovered threads. Shared across rebuilds while the
/// balancer's slots are unchanged.
#[derive(Default)]
pub struct LoadEwma {
	/// Smoothed permille (`None` = unknown) and the time of the pass that last updated it.
	state: Mutex<(Option<f64>, u64)>,
	/// Permille in the low 10 bits, monotonic ms until which it is current above them; 0 = unknown.
	published: AtomicU64,
}

impl LoadEwma {
	/// Current smoothed load in permille and the monotonic ms it is current until, or `None` when no
	/// discovered thread has a fresh sample.
	pub fn get(&self, now: u64) -> Option<(u32, u64)> {
		let packed = self.published.load(Ordering::Relaxed);
		let until_ms = packed >> 10;
		(now / 1_000_000 < until_ms).then_some(((packed & 0x3FF) as u32, until_ms))
	}

	#[cfg(test)]
	pub fn publish_for_test(&self, permille: u32, until_ms: u64) {
		self.published
			.store(until_ms << 10 | permille as u64, Ordering::Relaxed);
	}

	fn update(&self, mean: Option<u32>, now: u64) {
		let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
		let (previous, at) = *state;
		if now <= at {
			return;
		}
		let Some(mean) = mean else {
			*state = (previous, now);
			self.published.store(0, Ordering::Relaxed);
			return;
		};
		let value = match previous {
			Some(value) if now - at < 3 * LOAD_TIME_CONSTANT_NS as u64 => {
				let alpha = 1.0 - (-((now - at) as f64) / LOAD_TIME_CONSTANT_NS).exp();
				value + alpha * (mean as f64 - value)
			}
			_ => mean as f64,
		};
		*state = (Some(value), now);
		let permille = (value.round() as u64).min(1000);
		let until_ms = (now + SAMPLE_VALID_NS) / 1_000_000;
		self.published
			.store(until_ms << 10 | permille, Ordering::Relaxed);
	}
}

/// Discover, sample and smooth every monitored slot of the live table, every 250 ms. Discovery
/// connects run beside the sampling, never ahead of it: one slow socket must not leave every other
/// slot's load to expire.
pub async fn sample_periodically(live: Arc<LiveRouteTable>, mut shutdown: broadcast::Receiver<()>) {
	let proc = ProcFs::host();
	// Dropping it at shutdown aborts the connects still running.
	let mut discoveries = tokio::task::JoinSet::new();
	loop {
		tokio::select! {
			_ = shutdown.recv() => return,
			_ = tokio::time::sleep(SAMPLE_INTERVAL) => {}
		}
		while discoveries.try_join_next().is_some() {}
		let table = live.0.load_full();
		if table.monitored_balancers.is_empty() {
			continue;
		}
		let now = now_ns();
		for cpu in table
			.monitored_balancers
			.iter()
			.flat_map(|b| b.thread_cpus())
		{
			if discoveries.len() >= MAX_CONCURRENT_DISCOVERIES {
				break;
			}
			if cpu.begin_discovery(now) {
				let cpu = cpu.clone();
				discoveries.spawn(async move {
					let owner = socket_owner(cpu.path.clone()).await;
					cpu.finish_discovery(owner);
				});
			}
		}
		let proc = proc.clone();
		let pass = tokio::task::spawn_blocking(move || {
			sample_table(&table.monitored_balancers, now_ns(), &proc)
		});
		tokio::select! {
			_ = shutdown.recv() => return,
			_ = pass => {}
		}
	}
}

fn sample_table(balancers: &[Arc<crate::balancer::UdsBalancer>], now: u64, proc: &ProcFs) {
	let mut views = HashMap::new();
	for balancer in balancers {
		let mut sum = 0u64;
		let mut count = 0u64;
		for cpu in balancer.thread_cpus() {
			cpu.sample(now, proc, &mut views);
			if let Some(util) = cpu.load_sample(now) {
				sum += util as u64;
				count += 1;
			}
		}
		balancer
			.load()
			.update((count > 0).then(|| (sum / count) as u32), now);
	}
}

/// Connect and close at once, keeping only the owner's credentials.
async fn socket_owner(path: Arc<str>) -> Option<u32> {
	let stream = tokio::time::timeout(
		DISCOVERY_TIMEOUT,
		tokio::net::UnixStream::connect(path.as_ref()),
	)
	.await
	.ok()?
	.ok()?;
	let pid = stream.peer_cred().ok()?.pid()?;
	u32::try_from(pid).ok().filter(|pid| *pid > 0)
}

#[cfg(test)]
mod tests {
	use super::*;

	const S: u64 = 1_000_000_000;

	fn stat_line(comm: &str, ticks: (u64, u64), start: u64) -> String {
		// pid (comm) state ppid pgrp session tty tpgid flags minflt cminflt majflt cmajflt utime
		// stime cutime cstime priority nice threads itrealvalue starttime …
		format!(
			"42 ({comm}) S 1 1 1 0 -1 0 0 0 0 0 {} {} 0 0 20 0 4 0 {start} 0 0\n",
			ticks.0, ticks.1
		)
	}

	struct FakeProc {
		dir: PathBuf,
	}

	impl FakeProc {
		fn new(name: &str) -> Self {
			let dir =
				std::env::temp_dir().join(format!("symphony-proc-{name}-{}", std::process::id()));
			let _ = std::fs::remove_dir_all(&dir);
			std::fs::create_dir_all(&dir).unwrap();
			Self { dir }
		}

		fn proc(&self) -> ProcFs {
			ProcFs {
				root: self.dir.clone(),
			}
		}

		fn process(&self, host_pid: u32, nspid: &[u32]) {
			std::fs::create_dir_all(self.dir.join(format!("{host_pid}/task"))).unwrap();
			std::fs::write(
				self.dir.join(format!("{host_pid}/status")),
				format!("Name:\tnode\nNSpid:\t{}\n", join(nspid)),
			)
			.unwrap();
		}

		fn thread(&self, host_pid: u32, host_tid: u32, nspid: &[u32], ticks: u64, start: u64) {
			let dir = self.dir.join(format!("{host_pid}/task/{host_tid}"));
			std::fs::create_dir_all(&dir).unwrap();
			std::fs::write(dir.join("status"), format!("NSpid:\t{}\n", join(nspid))).unwrap();
			std::fs::write(dir.join("stat"), stat_line("node (x)", (ticks, 0), start)).unwrap();
		}
	}

	impl Drop for FakeProc {
		fn drop(&mut self) {
			let _ = std::fs::remove_dir_all(&self.dir);
		}
	}

	fn join(ids: &[u32]) -> String {
		ids.iter()
			.map(u32::to_string)
			.collect::<Vec<_>>()
			.join("\t")
	}

	#[test]
	fn task_stat_reads_cpu_ticks_and_start_past_a_comm_with_parentheses() {
		let stat = parse_task_stat(&stat_line("a) (b", (7, 5), 991)).unwrap();
		assert_eq!(
			stat,
			TaskStat {
				ticks: 12,
				start: 991
			}
		);
		assert!(parse_task_stat("42 (x) S 1").is_none());
	}

	#[test]
	fn nspid_lists_outermost_first() {
		assert_eq!(
			parse_nspid("Name:\tnode\nNSpid:\t3479404\t3\nTgid:\t1\n"),
			Some(vec![3479404, 3])
		);
		assert_eq!(parse_nspid("NSpid:\t12\n"), Some(vec![12]));
		assert_eq!(parse_nspid("Name:\tnode\n"), None);
		assert_eq!(parse_nspid("NSpid:\tx\n"), None);
	}

	#[test]
	fn configured_ids_in_the_host_namespace_are_used_as_is() {
		let fake = FakeProc::new("host");
		fake.process(500, &[500]);
		fake.thread(500, 510, &[510], 0, 77);
		let mut views = HashMap::new();
		assert_eq!(
			resolve(500, 510, 500, &fake.proc(), &mut views),
			Identity::Discovered {
				pid: 500,
				tid: 510,
				start: 77
			}
		);
		assert_eq!(
			resolve(500, 999, 500, &fake.proc(), &mut views),
			Identity::Unresolved,
			"a tid that is not (yet) a thread of the owner is looked up again soon"
		);
	}

	#[test]
	fn container_namespace_ids_are_translated_through_nspid() {
		let fake = FakeProc::new("ns");
		// Harper reported pid 7, tid 20 from inside its container.
		fake.process(3479403, &[3479403, 7]);
		fake.thread(3479403, 3479403, &[3479403, 7], 0, 50);
		fake.thread(3479403, 3479420, &[3479420, 20], 0, 60);
		let mut views = HashMap::new();
		assert_eq!(
			resolve(7, 20, 3479403, &fake.proc(), &mut views),
			Identity::Discovered {
				pid: 3479403,
				tid: 3479420,
				start: 60
			}
		);
		assert_eq!(views.len(), 1, "one scan per process");
		assert_eq!(
			resolve(7, 21, 3479403, &fake.proc(), &mut views),
			Identity::Unresolved
		);
	}

	#[test]
	fn ids_that_do_not_name_the_socket_owner_stay_literal() {
		let fake = FakeProc::new("mismatch");
		fake.process(600, &[600]);
		let mut views = HashMap::new();
		assert_eq!(
			resolve(42, 43, 600, &fake.proc(), &mut views),
			Identity::Literal
		);
		assert_eq!(
			resolve(42, 43, 601, &fake.proc(), &mut views),
			Identity::Unresolved,
			"owner gone, as during a restart: looked up again soon"
		);
	}

	#[test]
	fn a_discovered_thread_counts_as_load_until_its_id_is_reused() {
		let fake = FakeProc::new("reuse");
		fake.process(500, &[500]);
		fake.thread(500, 510, &[510], 100, 77);
		let proc = fake.proc();
		let cpu = ThreadCpu::new(Arc::from("/unused.sock"), 500, 510);
		let mut views = HashMap::new();
		cpu.apply_discovery(Some(500), 0, &proc, &mut views);

		let tick = clk_tck_hz();
		cpu.sample(1_000_000_000, &proc, &mut HashMap::new());
		assert_eq!(cpu.load_sample(1_000_000_000), None, "a baseline only");
		fake.thread(500, 510, &[510], 100 + tick / 2, 77);
		cpu.sample(2_000_000_000, &proc, &mut HashMap::new());
		assert_eq!(cpu.util_permille(), 500);
		assert_eq!(cpu.load_sample(2_000_000_000), Some(500));
		assert_eq!(cpu.load_sample(3_000_000_000), None, "stale");

		// The thread exits and its tid is reused by a thread started later.
		fake.thread(500, 510, &[510], 5, 99);
		cpu.sample(2_250_000_000, &proc, &mut HashMap::new());
		assert_eq!(
			cpu.util_permille(),
			0,
			"no value is kept for a thread that is gone"
		);
		assert_eq!(cpu.load_sample(2_250_000_000), None);
		assert!(cpu.discovery_due(2_250_000_000), "rediscovered");
	}

	#[test]
	fn a_literal_identity_never_counts_as_load() {
		let fake = FakeProc::new("literal");
		fake.process(600, &[600]);
		fake.process(42, &[42]);
		fake.thread(42, 43, &[43], 0, 1);
		let proc = fake.proc();
		let cpu = ThreadCpu::new(Arc::from("/unused.sock"), 42, 43);
		cpu.apply_discovery(Some(600), 0, &proc, &mut HashMap::new());
		cpu.sample(1_000_000_000, &proc, &mut HashMap::new());
		fake.thread(42, 43, &[43], clk_tck_hz(), 1);
		cpu.sample(2_000_000_000, &proc, &mut HashMap::new());
		assert_eq!(cpu.util_permille(), 1000, "still read for the tiebreak");
		assert_eq!(cpu.load_sample(2_000_000_000), None);
	}

	#[test]
	fn load_is_smoothed_and_unknown_without_fresh_samples() {
		let load = LoadEwma::default();
		assert_eq!(load.get(0), None);
		load.update(Some(1000), 1_000_000_000);
		assert_eq!(load.get(1_000_000_000), Some((1000, 2_000)));
		// One time constant at 0 moves it about 63 % of the way.
		load.update(Some(0), 4_000_000_000);
		assert_eq!(load.get(4_000_000_000).map(|l| l.0), Some(368));
		assert_eq!(load.get(5_000_000_000), None, "expired");
		load.update(None, 4_250_000_000);
		assert_eq!(load.get(4_250_000_000), None);
		load.update(Some(200), 60_000_000_000);
		assert_eq!(
			load.get(60_000_000_000).map(|l| l.0),
			Some(200),
			"restarts from the sample after a long gap"
		);
	}

	#[tokio::test]
	async fn the_socket_owner_is_read_from_its_credentials() {
		let dir = std::env::temp_dir().join(format!("symphony-owner-{}", std::process::id()));
		let _ = std::fs::remove_dir_all(&dir);
		std::fs::create_dir_all(&dir).unwrap();
		let path = dir.join("w.sock");
		let _listener = tokio::net::UnixListener::bind(&path).unwrap();
		assert_eq!(
			socket_owner(Arc::from(path.to_str().unwrap())).await,
			Some(std::process::id())
		);
		assert_eq!(socket_owner(Arc::from("/nonexistent/x.sock")).await, None);
		let _ = std::fs::remove_dir_all(&dir);
	}

	#[test]
	fn a_discovery_lands_on_the_next_pass_and_resolved_owners_are_rechecked() {
		let fake = FakeProc::new("pending");
		fake.process(500, &[500]);
		fake.thread(500, 510, &[510], 0, 77);
		let proc = fake.proc();
		let cpu = ThreadCpu::new(Arc::from("/unused.sock"), 500, 510);
		assert!(cpu.begin_discovery(0));
		assert!(!cpu.begin_discovery(1), "one at a time");
		cpu.finish_discovery(Some(500));
		cpu.sample(S, &proc, &mut HashMap::new());
		assert!(matches!(
			cpu.lock().identity,
			Identity::Discovered { pid: 500, .. }
		));
		assert!(!cpu.discovery_due(30 * S));
		assert!(cpu.discovery_due(31 * S), "the owner is checked again");

		// The same owner again keeps the baseline; a pass older than the last one changes nothing.
		cpu.sample(2 * S, &proc, &mut HashMap::new());
		cpu.finish_discovery(Some(500));
		cpu.sample(3 * S, &proc, &mut HashMap::new());
		assert_eq!(cpu.lock().last_ns, 3 * S);
		cpu.sample(2 * S, &proc, &mut HashMap::new());
		assert_eq!(cpu.lock().last_ns, 3 * S);

		let failed = ThreadCpu::new(Arc::from("/unused.sock"), 500, 510);
		failed.begin_discovery(0);
		failed.finish_discovery(None);
		failed.sample(S, &proc, &mut HashMap::new());
		assert!(
			failed.discovery_due(6 * S),
			"a failed connect is retried after 5 s"
		);
	}

	#[test]
	fn a_stale_pass_does_not_move_the_load() {
		let load = LoadEwma::default();
		load.update(Some(800), 2 * S);
		load.update(Some(0), S);
		load.update(None, S);
		assert_eq!(load.get(2 * S).map(|l| l.0), Some(800));
	}
}
