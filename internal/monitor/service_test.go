package monitor

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/notify"
)

// TestStateDerivation is the Task 9 brief's own table, as corrected by
// batch-3 review finding 1: with expectedCertificateId set, the leaf must
// match that certificate's current fingerprint; with it unset, the leaf
// must match *some* certificate's current version in the org
// (fpKnownInOrg) — "against no version in the org" was the wrong reading
// (it used to mean "skip the check"), not "there is nothing to mismatch
// against".
func TestStateDerivation(t *testing.T) {
	now := time.Now()
	soon := now.Add(7 * 24 * time.Hour) // inside ExpiringWithin (14d)
	far := now.Add(90 * 24 * time.Hour) // outside ExpiringWithin
	cases := []struct {
		name         string
		obs          Observation
		expectedFP   string
		hasExpected  bool
		fpKnownInOrg bool
		want         string
	}{
		{"unreachable wins over everything", Observation{Err: errors.New("dial: refused")}, "abc", true, false, "unreachable"},
		{"expected set and matches, far notAfter: ok", Observation{Fingerprint: "abc", NotAfter: far}, "abc", true, false, "ok"},
		{"expected set and differs: mismatch", Observation{Fingerprint: "def", NotAfter: far}, "abc", true, false, "mismatch"},
		{"expected unset, fp known in org, far notAfter: ok", Observation{Fingerprint: "anything", NotAfter: far}, "", false, true, "ok"},
		{"expected unset, fp not known in org: mismatch", Observation{Fingerprint: "anything", NotAfter: far}, "", false, false, "mismatch"},
		{"expiring within 14d, no expected, fp known", Observation{Fingerprint: "abc", NotAfter: soon}, "", false, true, "expiring"},
		{"expiring beats a matching expected (still within 14d)", Observation{Fingerprint: "abc", NotAfter: soon}, "abc", true, false, "expiring"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := deriveState(c.obs, c.expectedFP, c.hasExpected, c.fpKnownInOrg, now)
			if got != c.want {
				t.Errorf("deriveState() = %q, want %q", got, c.want)
			}
		})
	}
}

// TestRecoveredOnlyFromBad: shouldEmit only fires "ok" as a recovery from a
// bad state (mismatch/expiring/unreachable), never from unknown, and never
// for a no-op same-state recheck.
func TestRecoveredOnlyFromBad(t *testing.T) {
	cases := []struct {
		old, new string
		want     bool
	}{
		{"unknown", "ok", false},
		{"ok", "ok", false},
		{"mismatch", "ok", true},
		{"expiring", "ok", true},
		{"unreachable", "ok", true},
		{"unknown", "mismatch", true},
		{"unknown", "unreachable", true},
		{"unknown", "expiring", true},
		{"ok", "mismatch", true},
		{"ok", "expiring", true},
		{"ok", "unreachable", true},
		{"mismatch", "mismatch", false},
		{"mismatch", "unknown", false}, // deriveState never returns unknown, but the guard is explicit
	}
	for _, c := range cases {
		if got := shouldEmit(c.old, c.new); got != c.want {
			t.Errorf("shouldEmit(%q, %q) = %v, want %v", c.old, c.new, got, c.want)
		}
	}
}

func TestJitteredNextCheckWithinBounds(t *testing.T) {
	now := time.Now()
	for i := 0; i < 50; i++ {
		got := jitteredNextCheck(now, 300)
		min := now.Add(300 * time.Second)
		max := now.Add(330 * time.Second) // +10%
		if got.Before(min) || got.After(max) {
			t.Fatalf("jitteredNextCheck = %v, want within [%v, %v]", got, min, max)
		}
	}
}

// TestMonitorEventPayloadKeepsDetails builds each monitor event the way the
// service does and checks the channel payload keeps the fields it carries.
func TestMonitorEventPayloadKeepsDetails(t *testing.T) {
	m := Monitor{ID: uuid.New(), OrgID: uuid.New(), Name: "edge", Host: "edge.example", Port: 8443}
	reached := Observation{Fingerprint: "ab:cd", Issuer: "CN=Test CA", NotAfter: time.Now().Add(time.Hour), ChainError: "unknown authority"}
	down := Observation{Err: errors.New("dial: refused")}
	cases := []struct {
		state string
		obs   Observation
		keys  []string
	}{
		{"mismatch", reached, []string{"host", "port", "fp", "issuer", "notAfter", "chainError"}},
		{"expiring", reached, []string{"host", "port", "fp", "issuer", "notAfter", "chainError"}},
		{"ok", reached, []string{"host", "port", "fp", "issuer", "notAfter", "chainError"}},
		{"unreachable", down, []string{"host", "port", "error"}},
	}
	for _, c := range cases {
		t.Run(c.state, func(t *testing.T) {
			ev := buildEvent(m, c.state, c.obs, time.Now(), time.Now())
			var body struct {
				Details map[string]any `json:"details"`
			}
			if err := json.Unmarshal(notify.Payload(ev, notify.Target{}), &body); err != nil {
				t.Fatal(err)
			}
			for _, k := range c.keys {
				if _, ok := body.Details[k]; !ok {
					t.Errorf("payload details lack %q: %v", k, body.Details)
				}
			}
		})
	}
}

// TestEventSummaryExpired: an expired leaf keeps kind monitor.expiring but
// the summary says expired.
func TestEventSummaryExpired(t *testing.T) {
	m := Monitor{ID: uuid.New(), OrgID: uuid.New(), Name: "edge", Host: "edge.example", Port: 443}
	now := time.Now()
	past := buildEvent(m, "expiring", Observation{Fingerprint: "f", NotAfter: now.Add(-time.Hour)}, now, now)
	if past.Kind != "monitor.expiring" || past.Summary != "edge (edge.example:443) is expired" {
		t.Errorf("past: kind %q summary %q", past.Kind, past.Summary)
	}
	soon := buildEvent(m, "expiring", Observation{Fingerprint: "f", NotAfter: now.Add(time.Hour)}, now, now)
	if soon.Summary != "edge (edge.example:443) is expiring" {
		t.Errorf("soon: summary %q", soon.Summary)
	}
}
