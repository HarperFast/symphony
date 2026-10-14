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

// Memory-benchmark arm (`npm run build:bench-jemalloc`): the addon's Rust allocations go to jemalloc
// while Node's stay on the system allocator. Its symbols stay prefixed, so it never interposes
// malloc for the rest of the process.
#[cfg(feature = "jemalloc")]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;
