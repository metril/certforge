package notify_test

import (
	"testing"

	"github.com/metril/certforge/internal/notify"
)

func TestKindsAndSeverities(t *testing.T) {
	want := map[string]struct {
		severity string
		resource string
	}{
		"cert.issued":         {"info", "certificate"},
		"cert.renewal_failed": {"warning", "certificate"},
		"cert.expiring":       {"warning", "certificate"},
		"cert.expired":        {"critical", "certificate"},
		"deploy.failed":       {"warning", "grant"},
		"deploy.drift":        {"warning", "grant"},
		"client.offline":      {"warning", "client"},
		"agent.cert_expiring": {"warning", "client"},
		"monitor.mismatch":    {"critical", "monitor"},
		"monitor.unreachable": {"warning", "monitor"},
		"monitor.expiring":    {"warning", "monitor"},
		"monitor.recovered":   {"info", "monitor"},
		"backup.completed":    {"info", "backup"},
		"backup.failed":       {"critical", "backup"},
		"test":                {"info", "channel"},
	}

	if len(notify.Kinds) != 15 {
		t.Fatalf("len(Kinds) = %d, want 15", len(notify.Kinds))
	}
	seen := map[string]bool{}
	for _, k := range notify.Kinds {
		seen[k] = true
		w, ok := want[k]
		if !ok {
			t.Errorf("Kinds has unexpected kind %q", k)
			continue
		}
		if got := notify.SeverityOf(k); got != w.severity {
			t.Errorf("SeverityOf(%q) = %q, want %q", k, got, w.severity)
		}
		if got := notify.ResourceTypeOf(k); got != w.resource {
			t.Errorf("ResourceTypeOf(%q) = %q, want %q", k, got, w.resource)
		}
		if !notify.IsKind(k) {
			t.Errorf("IsKind(%q) = false, want true", k)
		}
	}
	for k := range want {
		if !seen[k] {
			t.Errorf("Kinds is missing %q", k)
		}
	}

	if notify.IsKind("bogus.kind") {
		t.Error("IsKind(bogus) = true, want false")
	}
	if notify.SeverityOf("bogus.kind") != "" {
		t.Error("SeverityOf(bogus) is non-empty")
	}
}

func TestSeverityRank(t *testing.T) {
	if notify.SeverityRank("info") >= notify.SeverityRank("warning") {
		t.Error("info should rank below warning")
	}
	if notify.SeverityRank("warning") >= notify.SeverityRank("critical") {
		t.Error("warning should rank below critical")
	}
	if notify.SeverityRank("bogus") != -1 {
		t.Error("SeverityRank(bogus) should be -1")
	}
}
