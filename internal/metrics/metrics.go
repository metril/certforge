package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Registry is CertForge's own Prometheus registry (Shared contract, GET
// /metrics): a dedicated registry, not prometheus.DefaultRegisterer, so
// nothing registered elsewhere (by a vendored library via promauto, for
// example) leaks into the scrape. It holds the Go and process collectors,
// the package-level counters/histogram below, the HTTP middleware's own
// series, and the database-backed Collector — registered once at boot by
// cmd/certforge/serve.go via NewCollector, since building it needs the
// pool and settings store.
var Registry = prometheus.NewRegistry()

var (
	// IssuanceAttempts is certforge_issuance_attempts_total{result}
	// (success|failed): internal/issuance/worker.go increments it once per
	// finished attempt.
	IssuanceAttempts = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certforge_issuance_attempts_total",
		Help: "Certificate issuance attempts by outcome.",
	}, []string{"result"})

	// IssuanceDuration is certforge_issuance_duration_seconds: one
	// observation per finished attempt (success or failure), from
	// internal/issuance/worker.go.
	IssuanceDuration = prometheus.NewHistogram(prometheus.HistogramOpts{
		Name:    "certforge_issuance_duration_seconds",
		Help:    "Certificate issuance attempt duration in seconds.",
		Buckets: prometheus.DefBuckets,
	})

	// NotificationsTotal is certforge_notifications_total{type,result}
	// (delivered|failed): internal/notify/deliver.go increments it once per
	// delivery attempt outcome.
	NotificationsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certforge_notifications_total",
		Help: "Notification delivery attempts by channel type and outcome.",
	}, []string{"type", "result"})

	// MonitorChecks is certforge_monitor_checks_total{result}: Phase 6A
	// Task 9's monitor service increments it once per check, result being
	// the resulting monitor state.
	MonitorChecks = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certforge_monitor_checks_total",
		Help: "External monitor checks by resulting state.",
	}, []string{"result"})

	// AuditHeadID is certforge_audit_head_id: the id of the newest audit
	// event this process has seen written or verified. Prometheus keeps its
	// history outside the database, so a drop (see docs/operations/monitoring.md) shows the
	// audit table was rolled back or truncated (docs/operations/security-model.md).
	AuditHeadID = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "certforge_audit_head_id",
		Help: "Id of the newest audit event written or verified by this process.",
	})

	// httpRequestsTotal and httpRequestDuration back Middleware:
	// certforge_http_requests_total{route,method,status} and
	// certforge_http_request_duration_seconds{route}. route is chi's route
	// pattern, never the raw path (Shared contract: bounded cardinality).
	httpRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "certforge_http_requests_total",
		Help: "HTTP requests by route, method and status.",
	}, []string{"route", "method", "status"})

	httpRequestDuration = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "certforge_http_request_duration_seconds",
		Help:    "HTTP request duration in seconds by route.",
		Buckets: prometheus.DefBuckets,
	}, []string{"route"})
)

func init() {
	Registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		IssuanceAttempts, IssuanceDuration, NotificationsTotal, MonitorChecks, AuditHeadID,
		httpRequestsTotal, httpRequestDuration,
	)
}
