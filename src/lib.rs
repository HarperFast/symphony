#![deny(clippy::all)]

#[macro_use]
extern crate napi_derive;

mod balancer;
mod bench_hooks;
mod error;
mod http_listener;
mod http_proxy;
mod listener;
mod liveness;
mod metrics;
mod mtls;
mod protection;
mod proxy;
mod proxy_conn;
mod router;
mod sni;
mod suspended;
mod tls;
mod upstream;

// glibc keeps the peak footprint resident after connections close: freed chunks stranded across its
// per-thread arenas are never returned to the OS. jemalloc returns them. Only the addon's Rust
// allocations move; its symbols stay prefixed, so Node's malloc is untouched, and nothing either
// side allocates is freed by the other (Rust↔JS values are copied, and napi finalizers run Rust drops).
#[cfg(all(target_os = "linux", feature = "jemalloc"))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[cfg(all(test, target_os = "linux", feature = "jemalloc"))]
mod allocator_tests {
	use std::ffi::{c_char, c_int, c_void};

	extern "C" {
		#[link_name = "_rjem_mallctl"]
		fn mallctl(
			name: *const c_char,
			oldp: *mut c_void,
			oldlenp: *mut usize,
			newp: *mut c_void,
			newlen: usize,
		) -> c_int;
	}

	/// Linking jemalloc is not selecting it: `arenas.lookup` only succeeds for memory jemalloc handed out.
	#[test]
	fn rust_allocations_come_from_jemalloc() {
		let boxed = Box::new([7u8; 64]);
		let mut ptr = boxed.as_ptr() as *const c_void;
		let mut arena: u32 = u32::MAX;
		let mut arena_len = std::mem::size_of::<u32>();
		let rc = unsafe {
			mallctl(
				c"arenas.lookup".as_ptr(),
				&mut arena as *mut u32 as *mut c_void,
				&mut arena_len,
				&mut ptr as *mut *const c_void as *mut c_void,
				std::mem::size_of::<*const c_void>(),
			)
		};
		assert_eq!(rc, 0, "a Box was not allocated by jemalloc");
		assert_ne!(arena, u32::MAX);
	}
}
