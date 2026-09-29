package monitor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/metrics"
	"github.com/metril/certforge/internal/notify"
	"github.com/metril/certforge/internal/settings"
)

// DialFunc dials host:port and observes its presented leaf (Observe's own
// signature); Service.Dial defaults to Observe and is overridden in tests
// that must not touch the real network (service_test.go).
type DialFunc func(host string, port int, sni string, allowLoopback bool) Observation

// Service runs a monitor's check: dial, derive state, compare-and-set,
// emit on a genuine transition (Shared contract's internal/monitor row).
// It does not itself do channel/event CRUD or authorization — the API
// layer's job, the same convention every other resource in this codebase
// follows (delivery.go's layouts/targets/hooks).
type Service struct {
	Store    *Store
	Emitter  *notify.Emitter
	Settings *settings.Store
	Now      func() time.Time
	Dial     DialFunc
}

func (s *Service) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Service) dial() DialFunc {
	if s.Dial != nil {
		return s.Dial
	}
	return Observe
}

// allowLoopback reads the live "notifications" section's allowLoopbackUrls
// (Deviations R5: monitor hosts share the notifier SSRF policy), never
// cached — an operator can flip it at any time.
func (s *Service) allowLoopback(ctx context.Context) (bool, error) {
	set, err := notify.Current(ctx, s.Settings)
	if err != nil {
		return false, err
	}
	return set.AllowLoopbackURLs, nil
}

// badStates are the states monitor.recovered may fire from (Task 9 brief:
// "recovered fires only from mismatch/expiring/unreachable to ok").
var badStates = map[string]bool{"mismatch": true, "expiring": true, "unreachable": true}

// deriveState computes a check's resulting state (Task 9 brief: "The state
// order is unreachable > mismatch > expiring > ok"). obs.Err set (the host
// was unreachable, or its own dial policy rejected it) always wins;
// otherwise a set expectedFingerprint that does not match obs.Fingerprint
// is a mismatch (Deviations R5: "against the expected certificate's
// current version, or, when unset, against no version in the org" — hasExpected
// false skips this check entirely); otherwise a leaf expiring within
// ExpiringWithin of now is expiring; otherwise ok.
func deriveState(obs Observation, expectedFingerprint string, hasExpected bool, now time.Time) string {
	if obs.Err != nil {
		return "unreachable"
	}
	if hasExpected && obs.Fingerprint != expectedFingerprint {
		return "mismatch"
	}
	if !obs.NotAfter.After(now.Add(ExpiringWithin)) {
		return "expiring"
	}
	return "ok"
}

// shouldEmit reports whether a check-driven state change from old to
// newState is event-worthy (Task 9 brief: "emits only when the row changed
// and the new state != unknown ... recovered fires only from
// mismatch/expiring/unreachable to ok"). newState is never itself "unknown"
// (deriveState never returns it), but the guard is kept explicit since it
// is part of the contract, not merely a consequence of deriveState's own
// range.
func shouldEmit(oldState, newState string) bool {
	if newState == oldState || newState == "unknown" {
		return false
	}
	if newState == "ok" {
		return badStates[oldState]
	}
	return true
}

// jitteredNextCheck is now plus intervalSeconds, plus up to 10% extra
// jitter (Task 9 brief: "next_check_at = now + interval + up to 10%
// jitter") — spreads a fleet of monitors sharing the same interval across
// the minute instead of all re-queuing on the exact same tick.
func jitteredNextCheck(now time.Time, intervalSeconds int) time.Time {
	base := time.Duration(intervalSeconds) * time.Second
	jitter := time.Duration(rand.Int63n(int64(base)/10 + 1)) //nolint:gosec // scheduling jitter, not security-sensitive
	return now.Add(base + jitter)
}

// monitorEventKind/monitorEventSuffix map a resulting state to its event
// kind and the dedupe key's own <state> segment (Shared contract's Dedupe
// keys row: "monitor.<state>:<monitorId>:<fp>:<state_changed_at unix>"; ok
// only ever gets here via shouldEmit's "recovered" gate, so its kind is
// monitor.recovered, not monitor.ok, which is not a declared EventKind).
func monitorEventKind(newState string) string {
	if newState == "ok" {
		return "monitor.recovered"
	}
	return "monitor." + newState
}

// Check dials id's monitor, derives its resulting state, applies the R5
// compare-and-set and — only on a genuine, won transition — emits the
// matching event. It always returns the monitor's current row (freshly
// re-read after the attempt), whether or not this call's own CAS won: a
// caller never needs to know which of two racing checks actually applied
// the write (Shared contract: "(*Service).Check(ctx, id) (Monitor, error)").
func (s *Service) Check(ctx context.Context, id uuid.UUID) (Monitor, error) {
	m, err := s.Store.GetByID(ctx, id)
	if err != nil {
		return Monitor{}, err
	}
	allowLoopback, err := s.allowLoopback(ctx)
	if err != nil {
		return Monitor{}, err
	}
	obs := s.dial()(m.Host, m.Port, effectiveSNI(m), allowLoopback)

	var expectedFP string
	hasExpected := m.ExpectedCertID != nil
	if hasExpected {
		fp, err := s.Store.CertificateFingerprint(ctx, *m.ExpectedCertID)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return Monitor{}, err
		}
		expectedFP = fp // "" (never matches) when the certificate has no current version
	}

	now := s.now()
	newState := deriveState(obs, expectedFP, hasExpected, now)
	metrics.MonitorChecks.WithLabelValues(newState).Inc()

	lastFP, lastIssuer, lastNotAfter, lastError := m.LastFingerprint, m.LastIssuer, m.LastNotAfter, ""
	if obs.Err == nil {
		lastFP = obs.Fingerprint
		lastIssuer = truncateUTF8(obs.Issuer, maxLastLen)
		notAfter := obs.NotAfter
		lastNotAfter = &notAfter
	} else {
		lastError = truncateUTF8(obs.Err.Error(), maxLastLen)
	}

	stateChangedAt := m.StateChangedAt
	if newState != m.State {
		stateChangedAt = now
	}
	nextCheckAt := jitteredNextCheck(now, m.IntervalSeconds)

	won, err := s.Store.TransitionState(ctx, TransitionParams{
		ID: id, OldState: m.State, NewState: newState, StateChangedAt: stateChangedAt, CheckedAt: now,
		NextCheckAt: nextCheckAt, LastFingerprint: lastFP, LastNotAfter: lastNotAfter, LastIssuer: lastIssuer, LastError: lastError,
	})
	if err != nil {
		return Monitor{}, err
	}
	if won && shouldEmit(m.State, newState) {
		s.emit(ctx, m, newState, obs, stateChangedAt)
	}
	return s.Store.GetByID(ctx, id)
}

// emit raises newState's event (task-9 brief: "Event details: host, port,
// fp, notAfter, issuer, chainError, error"). A failure here is logged by
// the caller's own river retry (a delivery worker failure never blocks the
// state write, which has already committed) — Emit itself is best-effort
// from Check's point of view, matching Sources.scan*'s own
// "log and continue" convention for every other event source.
func (s *Service) emit(ctx context.Context, m Monitor, newState string, obs Observation, stateChangedAt time.Time) {
	kind := monitorEventKind(newState)
	details := map[string]any{
		"host": m.Host, "port": m.Port, "fp": obs.Fingerprint, "issuer": obs.Issuer, "chainError": obs.ChainError,
	}
	if !obs.NotAfter.IsZero() {
		details["notAfter"] = obs.NotAfter
	}
	if obs.Err != nil {
		details["error"] = obs.Err.Error()
	}
	suffix := newState
	if newState == "ok" {
		suffix = "recovered"
	}
	ev := notify.Event{
		Kind: kind, OrgID: &m.OrgID, Resource: notify.Resource{ID: m.ID.String(), Name: m.Name},
		Summary:   fmt.Sprintf("%s (%s:%d) is %s", m.Name, m.Host, m.Port, suffix),
		Details:   details,
		DedupeKey: fmt.Sprintf("monitor.%s:%s:%s:%d", suffix, m.ID, obs.Fingerprint, stateChangedAt.Unix()),
	}
	if _, err := s.Emitter.Emit(ctx, nil, ev); err != nil {
		// Service has no *slog.Logger of its own (the Shared contract's
		// Service{Store, Emitter, Settings, Now, Dial} does not list one);
		// slog.Default() matches every other package's own fallback
		// (deploy.Dispatcher.log(), notify.Service.log()) when no logger is
		// configured.
		slog.Default().Error("monitor: event not emitted", "monitor", m.ID, "state", newState, "err", err)
	}
}
