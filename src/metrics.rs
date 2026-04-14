use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Default)]
pub struct ListenerMetrics {
	pub active_connections: AtomicU64,
	pub total_accepted: AtomicU64,
	pub total_blocked: AtomicU64,
	pub total_errors: AtomicU64,
}

impl ListenerMetrics {
	pub fn inc_active(&self) {
		self.active_connections.fetch_add(1, Ordering::Relaxed);
		self.total_accepted.fetch_add(1, Ordering::Relaxed);
	}

	pub fn dec_active(&self) {
		self.active_connections.fetch_sub(1, Ordering::Relaxed);
	}

	pub fn inc_blocked(&self) {
		self.total_blocked.fetch_add(1, Ordering::Relaxed);
	}

	pub fn inc_error(&self) {
		self.total_errors.fetch_add(1, Ordering::Relaxed);
	}
}

#[derive(Default)]
pub struct GlobalMetrics {
	pub active_connections: AtomicU64,
	pub total_blocked: AtomicU64,
	pub pending_suspended: AtomicU64,
}

impl GlobalMetrics {
	pub fn inc_active(&self) {
		self.active_connections.fetch_add(1, Ordering::Relaxed);
	}

	pub fn dec_active(&self) {
		self.active_connections.fetch_sub(1, Ordering::Relaxed);
	}

	pub fn inc_blocked(&self) {
		self.total_blocked.fetch_add(1, Ordering::Relaxed);
	}

	pub fn inc_suspended(&self) {
		self.pending_suspended.fetch_add(1, Ordering::Relaxed);
	}

	pub fn dec_suspended(&self) {
		self.pending_suspended.fetch_sub(1, Ordering::Relaxed);
	}
}
