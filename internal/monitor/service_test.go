package monitor

import (
	"errors"
	"testing"
	"time"
)

// TestStateDerivation is the Task 9 brief's own table: expected match/
// mismatch, unset expected matches none, expiring < 14 d, unreachable.
func TestStateDerivation(t *testing.T) {
	now := time.Now()
	soon := now.Add(7 * 24 * time.Hour) // inside ExpiringWithin (14d)
	far := now.Add(90 * 24 * time.Hour) // outside ExpiringWithin
	cases := []struct {
		name        string
		obs         Observation
		expectedFP  string
		hasExpected bool
		want        string
	}{
		{"unreachable wins over everything", Observation{Err: errors.New("dial: refused")}, "abc", true, "unreachable"},
		{"expected set and matches, far notAfter: ok", Observation{Fingerprint: "abc", NotAfter: far}, "abc", true, "ok"},
		{"expected set and differs: mismatch", Observation{Fingerprint: "def", NotAfter: far}, "abc", true, "mismatch"},
		{"expected unset: never mismatches, matches none", Observation{Fingerprint: "anything", NotAfter: far}, "", false, "ok"},
		{"expiring within 14d, no expected", Observation{Fingerprint: "abc", NotAfter: soon}, "", false, "expiring"},
		{"expiring beats a matching expected (still within 14d)", Observation{Fingerprint: "abc", NotAfter: soon}, "abc", true, "expiring"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := deriveState(c.obs, c.expectedFP, c.hasExpected, now)
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
