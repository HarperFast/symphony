export { SymphonyProxy } from './proxy.js';
export type {
	ProxyConfig,
	ListenerConfig,
	RouteConfig,
	Upstream,
	TcpUpstream,
	UdsUpstream,
	CertConfig,
	MtlsConfig,
	ProtectionConfig,
	RateLimitConfig,
	HotConfig,
	ProxyMetrics,
	ListenerMetrics,
	LabeledCount,
	BlockedIpsInfo,
	SuspendedConnection,
	ResolveRoute,
	ProxyEvent,
	BlockedEvent,
	SuspendedEvent,
	ErrorEvent,
} from './types.js';
// `renderPrometheus` and the standalone server's snapshot shape are deliberately NOT exported
// from the package root. They are an implementation detail of the symphony-server admin
// endpoint — a snapshot carries that process's pid, timestamps, and port-set grouping, which an
// embedded consumer would have to synthesise. Exporting them would make that shape a
// compatibility commitment with no caller asking for it; add a `ProxyMetrics`-based renderer
// interface if one ever does.
