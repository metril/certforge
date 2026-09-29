package notify

import (
	"time"

	"github.com/google/uuid"
)

// Kinds lists every EventKind, in the order the Shared contract's Enums row
// defines it (also the migration's CHECK constraint order): TestKindsAndSeverities
// pins this order and every kind's severity.
var Kinds = []string{
	"cert.issued", "cert.renewal_failed", "cert.expiring", "cert.expired",
	"deploy.failed", "deploy.drift", "client.offline", "agent.cert_expiring",
	"monitor.mismatch", "monitor.unreachable", "monitor.expiring", "monitor.recovered",
	"backup.completed", "backup.failed", "test",
}

// severityByKind is the Shared contract's "Severity and resource per kind" row.
var severityByKind = map[string]string{
	"cert.issued":         "info",
	"monitor.recovered":   "info",
	"backup.completed":    "info",
	"test":                "info",
	"cert.renewal_failed": "warning",
	"cert.expiring":       "warning",
	"deploy.failed":       "warning",
	"deploy.drift":        "warning",
	"client.offline":      "warning",
	"agent.cert_expiring": "warning",
	"monitor.unreachable": "warning",
	"monitor.expiring":    "warning",
	"cert.expired":        "critical",
	"monitor.mismatch":    "critical",
	"backup.failed":       "critical",
}

// resourceTypeByKind is the Shared contract's "Resources" mapping (same row).
var resourceTypeByKind = map[string]string{
	"cert.issued":         "certificate",
	"cert.renewal_failed": "certificate",
	"cert.expiring":       "certificate",
	"cert.expired":        "certificate",
	"deploy.failed":       "grant",
	"deploy.drift":        "grant",
	"client.offline":      "client",
	"agent.cert_expiring": "client",
	"monitor.mismatch":    "monitor",
	"monitor.unreachable": "monitor",
	"monitor.expiring":    "monitor",
	"monitor.recovered":   "monitor",
	"backup.completed":    "backup",
	"backup.failed":       "backup",
	"test":                "channel",
}

// severityRank orders Severity for the channel minSeverity comparison
// (Emit: "rank(min_severity) <= rank($sev)").
var severityRank = map[string]int{"info": 0, "warning": 1, "critical": 2}

// IsKind reports whether kind is one of Kinds.
func IsKind(kind string) bool {
	_, ok := severityByKind[kind]
	return ok
}

// SeverityOf returns kind's fixed severity, or "" for an unknown kind.
func SeverityOf(kind string) string { return severityByKind[kind] }

// ResourceTypeOf returns kind's fixed resource type, or "" for an unknown kind.
func ResourceTypeOf(kind string) string { return resourceTypeByKind[kind] }

// SeverityRank orders info < warning < critical, or -1 for an unknown value.
func SeverityRank(severity string) int {
	if r, ok := severityRank[severity]; ok {
		return r
	}
	return -1
}

// Resource names the thing an Event is about (Shared contract's Event.resource).
type Resource struct {
	Type string
	ID   string
	Name string
}

// Event is one notification-worthy occurrence (Shared contract's Event
// schema, minus the wire-only deliveries list DeliverWorker/the events API
// attach separately). DedupeKey is Emit's exact-once guard (Shared
// contract's "Dedupe keys" row); it is never sent to a channel.
type Event struct {
	ID        uuid.UUID
	Kind      string
	At        time.Time
	OrgID     *uuid.UUID
	Severity  string
	Resource  Resource
	Summary   string
	Details   map[string]any
	DedupeKey string
}
