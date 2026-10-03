//go:build integration

package issuance

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/challenge"
)

type fakeInserter struct {
	seen map[string]bool
	args []IssueArgs
}

func (f *fakeInserter) Insert(_ context.Context, a river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	ia := a.(IssueArgs)
	dup := f.seen[ia.CertID.String()]
	f.seen[ia.CertID.String()] = true
	f.args = append(f.args, ia)
	return &rivertype.JobInsertResult{Job: &rivertype.JobRow{}, UniqueSkippedAsDuplicate: dup}, nil
}

func TestEnqueueDue(t *testing.T) {
	f := newFixture(t)
	rules := []challenge.RuleSpec{{Match: "*", Method: challenge.MethodManualDNS}}
	due := f.cert(t, []string{"a.example.test"}, rules)
	later := f.cert(t, []string{"b.example.test"}, rules)
	if err := f.store.MarkFailed(context.Background(), later.ID, StatusFailed, 1, "x", time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	ins := &fakeInserter{seen: map[string]bool{}}
	n, err := EnqueueDue(context.Background(), f.store, ins, 100)
	if err != nil || n != 1 || len(ins.args) != 1 || ins.args[0].CertID != due.ID {
		t.Fatalf("n=%d args=%v err=%v", n, ins.args, err)
	}
	if n, _ := EnqueueDue(context.Background(), f.store, ins, 100); n != 0 {
		t.Fatalf("duplicate counted: %d", n)
	}
}

// TestEnqueueDueHousekeepingFailure: a failing housekeeping call (here the
// ledger prune, its table renamed away) is reported but never stops due
// certificates from being enqueued.
func TestEnqueueDueHousekeepingFailure(t *testing.T) {
	f := newFixture(t)
	rules := []challenge.RuleSpec{{Match: "*", Method: challenge.MethodManualDNS}}
	due := f.cert(t, []string{"a.example.test"}, rules)
	if _, err := f.pool.Exec(context.Background(), `ALTER TABLE rate_ledger RENAME TO rate_ledger_gone`); err != nil {
		t.Fatal(err)
	}
	ins := &fakeInserter{seen: map[string]bool{}}
	n, err := EnqueueDue(context.Background(), f.store, ins, 100)
	if err == nil {
		t.Fatal("want the housekeeping error returned")
	}
	if n != 1 || len(ins.args) != 1 || ins.args[0].CertID != due.ID {
		t.Fatalf("n=%d args=%v", n, ins.args)
	}
}

// TestEnqueueDueHousekeepingTimeout: a prune step stuck on a lock times out
// on its own budget; due certificates are enqueued anyway.
func TestEnqueueDueHousekeepingTimeout(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	rules := []challenge.RuleSpec{{Match: "*", Method: challenge.MethodManualDNS}}
	due := f.cert(t, []string{"a.example.test"}, rules)
	tx, err := f.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck // best-effort test cleanup
	if _, err := tx.Exec(ctx, `LOCK TABLE rate_ledger IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	old := housekeepingStepTimeout
	housekeepingStepTimeout = 300 * time.Millisecond
	defer func() { housekeepingStepTimeout = old }()
	ins := &fakeInserter{seen: map[string]bool{}}
	n, err := EnqueueDue(ctx, f.store, ins, 100)
	if err == nil {
		t.Fatal("want the timed-out step reported")
	}
	if n != 1 || len(ins.args) != 1 || ins.args[0].CertID != due.ID {
		t.Fatalf("n=%d args=%v", n, ins.args)
	}
}

func TestScheduleWorkerTimeout(t *testing.T) {
	if got := (&ScheduleWorker{}).Timeout(nil); got != scheduleTimeout {
		t.Fatalf("Timeout = %v, want %v", got, scheduleTimeout)
	}
}

// TestSchedulerSkipsUnmanaged is R10: an unmanaged (uploaded/imported)
// certificate never appears in ListDueCertificateIDs/EnqueueDue, whatever
// it might otherwise look due for (the certificates_unmanaged_no_renewal
// CHECK constraint already keeps its next_renew_at NULL; this exercises
// the explicit ListDueCertificateIDs "AND managed" defense in depth end to
// end, through EnqueueDue itself).
func TestSchedulerSkipsUnmanaged(t *testing.T) {
	f := newFixture(t)
	rules := []challenge.RuleSpec{{Match: "*", Method: challenge.MethodManualDNS}}
	due := f.cert(t, []string{"a.example.test"}, rules)

	tx, err := f.store.Begin(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.store.CreateExternalCertificate(context.Background(), tx, f.org, "unmanaged", "u.example.test", []string{}, Defaults{}, false, StatusActive, nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(context.Background()); err != nil {
		t.Fatal(err)
	}

	ins := &fakeInserter{seen: map[string]bool{}}
	n, err := EnqueueDue(context.Background(), f.store, ins, 100)
	if err != nil || n != 1 || len(ins.args) != 1 || ins.args[0].CertID != due.ID {
		t.Fatalf("n=%d args=%v err=%v", n, ins.args, err)
	}
}

func TestIssueArgsUniqueExcludesCompleted(t *testing.T) {
	o := IssueArgs{}.InsertOpts()
	if !o.UniqueOpts.ByArgs || slices.Contains(o.UniqueOpts.ByState, rivertype.JobStateCompleted) {
		t.Fatalf("unique opts = %+v", o.UniqueOpts)
	}
	for _, s := range []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending, rivertype.JobStateRunning, rivertype.JobStateScheduled} {
		if !slices.Contains(o.UniqueOpts.ByState, s) {
			t.Fatalf("river requires state %s", s)
		}
	}
}
