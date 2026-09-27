package issuance

import (
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/signer"
)

var t0 = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

func TestNextRenewAt(t *testing.T) {
	day := 24 * time.Hour
	cases := []struct {
		name string
		p    RenewPolicy
		life time.Duration
		now  time.Time
		want time.Time
	}{
		{"percent 33 of 90d", RenewPolicy{Mode: RenewPercent, Value: 33}, 90 * day, t0, t0.Add(90*day - 90*day*33/100)},
		{"days 30 of 90d", RenewPolicy{Mode: RenewDays, Value: 30}, 90 * day, t0, t0.Add(60 * day)},
		{"days 30 of 6d clamps to half life", RenewPolicy{Mode: RenewDays, Value: 30}, 6 * day, t0, t0.Add(3 * day)},
		{"percent 0 falls back to 33", RenewPolicy{Mode: RenewPercent}, 100 * day, t0, t0.Add(67 * day)},
		{"never before now+1h", RenewPolicy{Mode: RenewPercent, Value: 33}, 90 * day, t0.Add(89 * day), t0.Add(89*day + time.Hour)},
		// Review Focus: life*time.Duration(v) overflows int64 nanoseconds for a
		// large lifetime; dividing life by 100 before multiplying keeps it sane.
		{"percent large life does not overflow", RenewPolicy{Mode: RenewPercent, Value: 33}, 200 * 365 * day, t0, t0.Add(200*365*day - 200*365*day/100*33)},
	}
	for _, c := range cases {
		got := NextRenewAt(c.p, t0, t0.Add(c.life), c.now)
		if !got.Equal(c.want) {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestBackoff(t *testing.T) {
	mid := func() float64 { return 0.5 } // no jitter
	for n, want := range map[int]time.Duration{0: 5 * time.Minute, 1: 5 * time.Minute, 2: 10 * time.Minute, 4: 40 * time.Minute, 10: 24 * time.Hour, 40: 24 * time.Hour} {
		if got := Backoff(n, 0, mid); got != want {
			t.Errorf("Backoff(%d) = %v want %v", n, got, want)
		}
	}
	if lo := Backoff(1, 0, func() float64 { return 0 }); lo != 4*time.Minute {
		t.Errorf("min jitter = %v", lo)
	}
	if hi := Backoff(1, 0, func() float64 { return 0.999999 }); hi < 5*time.Minute || hi > 6*time.Minute {
		t.Errorf("max jitter = %v", hi)
	}
	// Review Focus: 429 with Retry-After beats the 5-minute first backoff.
	if got := Backoff(1, 3*time.Hour, mid); got != 3*time.Hour {
		t.Errorf("Retry-After ignored: %v", got)
	}
}

func TestNextRenewAtARI(t *testing.T) {
	hour := time.Hour
	policyAt := t0.Add(10 * hour)
	mid := func() float64 { return 0.5 } // deterministic midpoint

	// Window before policy: inside the window.
	w := &signer.Window{Start: t0.Add(2 * hour), End: t0.Add(4 * hour)}
	if got := NextRenewAtARI(policyAt, w, t0, mid); got.Before(w.Start) || got.After(w.End) {
		t.Errorf("before: got %v, want inside [%v,%v]", got, w.Start, w.End)
	}
	if got := NextRenewAtARI(policyAt, w, t0, mid); !got.Equal(w.Start.Add(w.End.Sub(w.Start) / 2)) {
		t.Errorf("before (midpoint): got %v, want %v", got, w.Start.Add(w.End.Sub(w.Start)/2))
	}

	// Window ending at or after policy: policy unchanged.
	after := &signer.Window{Start: t0.Add(9 * hour), End: t0.Add(11 * hour)}
	if got := NextRenewAtARI(policyAt, after, t0, mid); !got.Equal(policyAt) {
		t.Errorf("after: got %v, want %v", got, policyAt)
	}
	same := &signer.Window{Start: t0.Add(9 * hour), End: policyAt}
	if got := NextRenewAtARI(policyAt, same, t0, mid); !got.Equal(policyAt) {
		t.Errorf("end == policy: got %v, want %v", got, policyAt)
	}

	// Nil window: policy unchanged.
	if got := NextRenewAtARI(policyAt, nil, t0, mid); !got.Equal(policyAt) {
		t.Errorf("nil: got %v, want %v", got, policyAt)
	}

	// A window that has fully passed collapses to now.
	past := &signer.Window{Start: t0.Add(-2 * hour), End: t0.Add(-hour)}
	now := t0.Add(5 * hour)
	if got := NextRenewAtARI(policyAt, past, now, mid); !got.Equal(now) {
		t.Errorf("past: got %v, want now %v", got, now)
	}
}

func TestResolveSources(t *testing.T) {
	ca := uuid.New()
	orgKT := signer.RSA2048
	certKT := signer.EC384
	ttl := 300
	global := Defaults{CAID: &ca, PropagationSeconds: &ttl}
	org := Defaults{KeyType: &orgKT}

	e := Resolve(global, org, Defaults{})
	if *e.CAID.Value != ca || e.CAID.Source != SourceGlobal {
		t.Errorf("caId = %+v", e.CAID)
	}
	if e.KeyType.Value != signer.RSA2048 || e.KeyType.Source != SourceOrg {
		t.Errorf("keyType = %+v", e.KeyType)
	}
	if e.PropagationSeconds.Value != 300 || e.RenewPolicy.Value.Mode != RenewPercent || e.RenewPolicy.Source != SourceDefault {
		t.Errorf("fallbacks wrong: %+v %+v", e.PropagationSeconds, e.RenewPolicy)
	}
	if e.AccountID.Value != nil || e.AccountID.Source != SourceDefault {
		t.Errorf("unset account = %+v", e.AccountID)
	}

	e = Resolve(global, org, Defaults{KeyType: &certKT})
	if e.KeyType.Value != signer.EC384 || e.KeyType.Source != SourceCert {
		t.Errorf("cert override lost: %+v", e.KeyType)
	}
}
