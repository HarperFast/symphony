//! Memory-benchmark hooks for `__test__/bench-copy-memory-oop.ts`. Each is inert unless its
//! environment variable is set, and none is a supported configuration surface: they exist to price
//! a lever before anyone proposes it as a default.

use std::time::Duration;
use tokio::sync::broadcast;

/// Caps rustls' per-connection outgoing queues (`ConnectionCommon::set_buffer_limit`). Unset, rustls
/// queues up to 64 KiB of TLS records — what a client that stops reading can pin per connection.
pub const TLS_BUFFER_LIMIT_ENV: &str = "SYMPHONY_TLS_BUFFER_LIMIT";
/// Period of a `malloc_trim(0)` call while the proxy is started. glibc only.
pub const MALLOC_TRIM_INTERVAL_ENV: &str = "SYMPHONY_MALLOC_TRIM_INTERVAL_MS";

/// rustls accepts no plaintext while its queue is at the limit, and tokio-rustls retries a write that
/// was accepted nowhere without yielding — so a limit of 0 spins a worker. A floor this size also
/// keeps the copy loop from degenerating into one tiny record per write.
const MIN_TLS_BUFFER_LIMIT: u64 = 1024;
const MIN_MALLOC_TRIM_INTERVAL_MS: u64 = 100;

const MALLOC_TRIM_SUPPORTED: bool = cfg!(all(target_os = "linux", target_env = "gnu"));

fn parse_at_least(name: &str, raw: Option<&str>, min: u64) -> Result<Option<u64>, String> {
	let Some(raw) = raw else {
		return Ok(None);
	};
	match raw.trim().parse::<u64>() {
		Ok(value) if value >= min => Ok(Some(value)),
		_ => Err(format!("{name} must be an integer >= {min}, got '{raw}'")),
	}
}

pub fn tls_buffer_limit() -> Result<Option<usize>, String> {
	let raw = std::env::var(TLS_BUFFER_LIMIT_ENV).ok();
	Ok(
		parse_at_least(TLS_BUFFER_LIMIT_ENV, raw.as_deref(), MIN_TLS_BUFFER_LIMIT)?
			.map(|v| v as usize),
	)
}

pub fn malloc_trim_interval() -> Result<Option<Duration>, String> {
	let raw = std::env::var(MALLOC_TRIM_INTERVAL_ENV).ok();
	let ms = parse_at_least(
		MALLOC_TRIM_INTERVAL_ENV,
		raw.as_deref(),
		MIN_MALLOC_TRIM_INTERVAL_MS,
	)?;
	if ms.is_some() && !MALLOC_TRIM_SUPPORTED {
		return Err(format!(
			"{MALLOC_TRIM_INTERVAL_ENV} needs glibc's malloc_trim, which this build does not link"
		));
	}
	Ok(ms.map(Duration::from_millis))
}

/// `malloc_trim(0)` also returns free pages from the middle of every arena, which glibc's automatic
/// trim (top of the heap only) never does — that retained memory is what the trim arm measures. The
/// trim is process-wide, so it reaches Node's allocations too, and several started proxies each run
/// their own loop.
pub async fn trim_periodically(interval: Duration, mut shutdown: broadcast::Receiver<()>) {
	loop {
		tokio::select! {
			_ = shutdown.recv() => break,
			_ = tokio::time::sleep(interval) => {
				// Off the worker threads: the call holds each arena's lock while it walks that arena.
				let _ = tokio::task::spawn_blocking(trim_once).await;
			}
		}
	}
}

#[cfg(all(target_os = "linux", target_env = "gnu"))]
fn trim_once() {
	let start = std::time::Instant::now();
	// SAFETY: no preconditions; glibc serialises it against malloc/free per arena.
	let released = unsafe { libc::malloc_trim(0) } == 1;
	// The duration is the cost a production lever would pay, so the benchmark collects it.
	tracing::info!(
		"malloc_trim elapsed_us={} released={released}",
		start.elapsed().as_micros()
	);
}

/// Never scheduled: `malloc_trim_interval` rejects the variable on these targets.
#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
fn trim_once() {}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn unset_is_off() {
		assert_eq!(parse_at_least("X", None, 1024), Ok(None));
	}

	#[test]
	fn accepts_values_at_or_above_the_floor() {
		assert_eq!(parse_at_least("X", Some("1024"), 1024), Ok(Some(1024)));
		assert_eq!(parse_at_least("X", Some(" 16384 "), 1024), Ok(Some(16384)));
	}

	#[test]
	fn rejects_zero_below_floor_negative_fractional_and_garbage() {
		for raw in [
			"0",
			"1023",
			"-1",
			"1.5",
			"16k",
			"",
			"99999999999999999999999",
		] {
			assert!(
				parse_at_least("X", Some(raw), 1024).is_err(),
				"'{raw}' must be rejected"
			);
		}
	}
}
