package audit_test

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/metril/certforge/internal/audit"
)

// TestDisabledAuditorRecordRefuses covers I2: an Auditor built with
// NewDisabled (a failed KEK canary at startup) must refuse every Record
// call with ErrAuditUnavailable, and must never touch the database to do
// so — a nil pool proves Record returns before any query runs, which is
// what keeps a wrong-KEK boot from ever writing a row keyed wrong.
func TestDisabledAuditorRecordRefuses(t *testing.T) {
	a := audit.NewDisabled(nil, bytes.Repeat([]byte{7}, 32))
	err := a.Record(context.Background(), audit.Event{Action: "session.login", ResourceType: "user"})
	if !errors.Is(err, audit.ErrAuditUnavailable) {
		t.Fatalf("expected ErrAuditUnavailable, got %v", err)
	}
}

// TestDisabledAuditorRechainRefuses is belt-and-braces alongside serve's own
// canaryOK gate around the Rechain call: Rechain on a disabled Auditor must
// also refuse outright, without touching the database.
func TestDisabledAuditorRechainRefuses(t *testing.T) {
	a := audit.NewDisabled(nil, bytes.Repeat([]byte{7}, 32))
	if _, err := a.Rechain(context.Background()); !errors.Is(err, audit.ErrAuditUnavailable) {
		t.Fatalf("expected ErrAuditUnavailable, got %v", err)
	}
}

// TestNewDisabledPanicsOnEmptyKey mirrors New's own contract: a disabled
// Auditor still requires a non-empty key argument (used only if Check/Verify
// are later called against it), so a caller cannot accidentally construct
// one with a nil key and have it look valid.
func TestNewDisabledPanicsOnEmptyKey(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on empty key")
		}
	}()
	audit.NewDisabled(nil, nil)
}
