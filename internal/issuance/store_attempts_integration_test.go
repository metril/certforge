//go:build integration

package issuance

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/dbtest"
)

func TestAttemptLifecycle(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c, err := f.store.CreateCertificate(ctx, f.org, CertInput{Name: "web", CommonName: "example.test"})
	if err != nil {
		t.Fatal(err)
	}

	id, err := f.store.CreateAttempt(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}

	running := []Step{{Name: "order", Status: challenge.StepRunning, StartedAt: time.Now().UTC()}}
	if err := f.store.SaveAttemptProgress(ctx, nil, id, running, "started\n"); err != nil {
		t.Fatal(err)
	}

	finished := []Step{{Name: "order", Status: challenge.StepSuccess, StartedAt: running[0].StartedAt}}
	if err := f.store.FinishAttempt(ctx, nil, id, OutcomeSuccess, "", nil, finished, "started\nfinished\n"); err != nil {
		t.Fatal(err)
	}

	attempts, err := f.store.ListAttempts(ctx, f.org, c.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 {
		t.Fatalf("attempts = %+v", attempts)
	}
	a := attempts[0]
	if a.Outcome != OutcomeSuccess || a.FinishedAt == nil || len(a.Steps) != 1 || a.Steps[0].Status != challenge.StepSuccess || a.Steps[0].Name != "order" {
		t.Fatalf("attempt = %+v", a)
	}
}

// Review Focus (fix round 1): ListAttempts is org-scoped through the
// certificate; a certificate id from another org must come back ErrNotFound.
func TestListAttemptsOrgScoped(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c, err := f.store.CreateCertificate(ctx, f.org, CertInput{Name: "web", CommonName: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateAttempt(ctx, c.ID); err != nil {
		t.Fatal(err)
	}

	otherOrg := dbtest.Org(t, f.pool)
	if _, err := f.store.ListAttempts(ctx, otherOrg, c.ID, 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-org ListAttempts: %v", err)
	}
}

func TestFailStaleAttempts(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c, err := f.store.CreateCertificate(ctx, f.org, CertInput{Name: "web", CommonName: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateAttempt(ctx, c.ID); err != nil {
		t.Fatal(err)
	}

	// A negative olderThan makes the cutoff later than now, so the
	// just-created "running" attempt counts as stale without a sleep.
	n, err := f.store.FailStaleAttempts(ctx, -time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("failed %d attempts, want 1", n)
	}

	attempts, err := f.store.ListAttempts(ctx, f.org, c.ID, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 1 || attempts[0].Outcome != OutcomeFailed || attempts[0].FinishedAt == nil {
		t.Fatalf("attempts = %+v", attempts)
	}
}

// Review Focus (fix round 1): the ManualStore trio (InsertManualPending,
// ManualConfirmed, DeleteManualPending) that challenge.ManualProvider relies
// on, plus the operator-facing ManualPending/ConfirmManual pair.
func TestManualStoreTrio(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	c, err := f.store.CreateCertificate(ctx, f.org, CertInput{Name: "web", CommonName: "example.test"})
	if err != nil {
		t.Fatal(err)
	}
	attemptID, err := f.store.CreateAttempt(ctx, c.ID)
	if err != nil {
		t.Fatal(err)
	}

	rec := challenge.ManualRecord{AttemptID: attemptID, CertID: c.ID, Domain: "example.test",
		FQDN: "_acme-challenge.example.test", Value: "abc", TTL: 120, ExpiresAt: time.Now().Add(time.Hour)}
	if err := f.store.InsertManualPending(ctx, rec); err != nil {
		t.Fatal(err)
	}

	pending, err := f.store.ManualPending(ctx, f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 || pending[0].Name != rec.FQDN || pending[0].Value != rec.Value || pending[0].TTL != rec.TTL {
		t.Fatalf("pending = %+v", pending)
	}

	confirmed, err := f.store.ManualConfirmed(ctx, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if confirmed {
		t.Fatal("confirmed before ConfirmManual")
	}

	n, err := f.store.ConfirmManual(ctx, f.org, c.ID)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("confirmed %d records, want 1", n)
	}

	confirmed, err = f.store.ManualConfirmed(ctx, attemptID)
	if err != nil {
		t.Fatal(err)
	}
	if !confirmed {
		t.Fatal("not confirmed after ConfirmManual")
	}

	if err := f.store.DeleteManualPending(ctx, attemptID); err != nil {
		t.Fatal(err)
	}
	// Deleting again affects zero rows and must still return nil.
	if err := f.store.DeleteManualPending(ctx, attemptID); err != nil {
		t.Fatalf("delete of zero rows: %v", err)
	}
}
