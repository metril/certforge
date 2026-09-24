package challenge

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/google/uuid"
)

// DefaultManualWait is how long an operator has to add and confirm records.
const DefaultManualWait = time.Hour

// ErrManualTimeout means nobody confirmed the manual-dns records in time.
var ErrManualTimeout = errors.New("manual-dns: TXT records were not confirmed in time")

// ManualRecord is one TXT record the operator must create.
type ManualRecord struct {
	AttemptID, CertID uuid.UUID
	Domain            string
	FQDN              string // without trailing dot
	Value             string
	TTL               int
	ExpiresAt         time.Time
}

// ManualStore persists pending records; issuance.Store implements it.
type ManualStore interface {
	InsertManualPending(ctx context.Context, r ManualRecord) error
	ManualConfirmed(ctx context.Context, attemptID uuid.UUID) (bool, error)
	DeleteManualPending(ctx context.Context, attemptID uuid.UUID) error
}

// ManualProvider records TXT records for the operator and blocks the first
// propagation check until POST .../manual-dns/confirm or the deadline.
type ManualProvider struct {
	Store     ManualStore
	AttemptID uuid.UUID
	CertID    uuid.UUID
	Wait      time.Duration
	Poll      time.Duration
	Now       func() time.Time

	mu       sync.Mutex
	deadline time.Time
	once     sync.Once
	ran      atomic.Bool // WaitReady has run to completion
	err      error
}

// NewManual returns a ManualProvider with default timings.
func NewManual(store ManualStore, attemptID, certID uuid.UUID) *ManualProvider {
	return &ManualProvider{Store: store, AttemptID: attemptID, CertID: certID, Wait: DefaultManualWait, Poll: 2 * time.Second, Now: time.Now}
}

// Type implements ChallengeProvider.
func (m *ManualProvider) Type() Type { return ManualDNS }

// Timeout implements ChallengeProvider; WaitBudget carries the operator's
// wait time separately so the router can add it to lego's propagation
// timeout without inflating lego's own polling interval.
func (m *ManualProvider) Timeout() (time.Duration, time.Duration) {
	return dns01.DefaultPropagationTimeout, dns01.DefaultPollingInterval
}

// WaitBudget implements Waiter.
func (m *ManualProvider) WaitBudget() time.Duration { return m.Wait }

// Present implements ChallengeProvider: it only records the pending row; lego
// calls Present for every name before any PreCheck runs.
func (m *ManualProvider) Present(ctx context.Context, domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	m.mu.Lock()
	if m.deadline.IsZero() {
		m.deadline = m.Now().Add(m.Wait)
	}
	dl := m.deadline
	m.mu.Unlock()
	return m.Store.InsertManualPending(ctx, ManualRecord{
		AttemptID: m.AttemptID, CertID: m.CertID, Domain: domain,
		FQDN: dns01.UnFqdn(info.EffectiveFQDN), Value: info.Value, TTL: dns01.DefaultTTL, ExpiresAt: dl,
	})
}

// CleanUp drops the pending rows; the operator removes the records by hand.
func (m *ManualProvider) CleanUp(ctx context.Context, _, _, _ string) error {
	return m.Store.DeleteManualPending(context.WithoutCancel(ctx), m.AttemptID)
}

// WaitReady implements Waiter. It blocks until every record of the attempt is
// confirmed. The result is cached: after a timeout, later calls fail
// immediately without waiting again.
func (m *ManualProvider) WaitReady(ctx context.Context) error {
	m.once.Do(func() {
		m.err = m.wait(ctx)
		m.ran.Store(true)
	})
	return m.err
}

// Outcome returns the error WaitReady recorded, but only once WaitReady has
// actually run to completion; it is nil both when WaitReady succeeded and
// when WaitReady was never called (for example because the CA reused an
// existing valid authorization and lego never asked this provider to solve
// one), so a caller cannot mistake "never ran" for "succeeded". It never
// blocks.
func (m *ManualProvider) Outcome() error {
	if !m.ran.Load() {
		return nil
	}
	return m.err
}

func (m *ManualProvider) wait(ctx context.Context) error {
	m.mu.Lock()
	dl := m.deadline
	m.mu.Unlock()
	for {
		ok, err := m.Store.ManualConfirmed(ctx, m.AttemptID)
		if err != nil {
			return err
		}
		if ok {
			return nil
		}
		if !m.Now().Before(dl) {
			_ = m.Store.DeleteManualPending(context.WithoutCancel(ctx), m.AttemptID)
			return fmt.Errorf("%w (waited %s)", ErrManualTimeout, m.Wait)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(m.Poll):
		}
	}
}
