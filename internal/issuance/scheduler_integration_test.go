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
