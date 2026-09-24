package challenge

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/google/uuid"
)

type memManual struct {
	mu        sync.Mutex
	rows      []ManualRecord
	confirmed bool
	deleted   int
}

func (s *memManual) InsertManualPending(_ context.Context, r ManualRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows = append(s.rows, r)
	return nil
}

func (s *memManual) ManualConfirmed(context.Context, uuid.UUID) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.confirmed, nil
}

func (s *memManual) DeleteManualPending(context.Context, uuid.UUID) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleted++
	s.rows = nil
	return nil
}

func (s *memManual) confirm() {
	s.mu.Lock()
	s.confirmed = true
	s.mu.Unlock()
}

type stepCall struct{ name, status, message string }

type sinkRec struct {
	mu    sync.Mutex
	steps map[string]string
	calls []stepCall
}

func (s *sinkRec) Step(name, status, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.steps == nil {
		s.steps = map[string]string{}
	}
	s.steps[name] = status
	s.calls = append(s.calls, stepCall{name, status, message})
}

// count returns how many times Step was called for name with status.
func (s *sinkRec) count(name, status string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, c := range s.calls {
		if c.name == name && c.status == status {
			n++
		}
	}
	return n
}

// lastMessage returns the message of the most recent Step call for name.
func (s *sinkRec) lastMessage(name string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	msg := ""
	for _, c := range s.calls {
		if c.name == name {
			msg = c.message
		}
	}
	return msg
}

func manualRouterCtx(ctx context.Context, t *testing.T, store *memManual, wait time.Duration) (*Router, *ManualProvider, *sinkRec) {
	t.Helper()
	mp := NewManual(store, uuid.New(), uuid.New())
	mp.Wait, mp.Poll = wait, 5*time.Millisecond
	sink := &sinkRec{}
	r := NewRouter(ctx, []string{"lab.example.test"}, []Rule{rule(t, "*", mp)}, sink)
	return r, mp, sink
}

func manualRouter(t *testing.T, store *memManual, wait time.Duration) (*Router, *ManualProvider, *sinkRec) {
	t.Helper()
	return manualRouterCtx(context.Background(), t, store, wait)
}

func TestManualConfirmResumes(t *testing.T) {
	store := &memManual{}
	r, _, sink := manualRouter(t, store, time.Minute)
	if err := r.Present("lab.example.test", "tok", "keyauth"); err != nil {
		t.Fatal(err)
	}
	want := dns01.GetChallengeInfo("lab.example.test", "keyauth")
	if len(store.rows) != 1 ||
		store.rows[0].FQDN != "_acme-challenge.lab.example.test" ||
		store.rows[0].Value != want.Value ||
		store.rows[0].TTL != dns01.DefaultTTL {
		t.Fatalf("rows = %+v, want value %q ttl %d", store.rows, want.Value, dns01.DefaultTTL)
	}
	if sink.steps["challenge lab.example.test"] != StepWaitingManual {
		t.Fatalf("step = %q", sink.steps["challenge lab.example.test"])
	}
	go func() { time.Sleep(20 * time.Millisecond); store.confirm() }()
	ok, err := r.PreCheck("lab.example.test", "_acme-challenge.lab.example.test.", "v", func(string, string) (bool, error) { return true, nil })
	if !ok || err != nil {
		t.Fatalf("PreCheck = %v, %v", ok, err)
	}
}

// Review Focus: lego's wait.For ignores a PreCheck error and keeps polling
// until its own (much longer) timeout, so a manual-dns timeout must make
// PreCheck report ready=true (after recording the failure) instead of
// returning an error, and the step must be marked failed exactly once even
// though the cached Waiter error is returned again on every later call.
func TestManualTimeoutFailsFastAfterDeadline(t *testing.T) {
	store := &memManual{}
	r, mp, sink := manualRouter(t, store, 30*time.Millisecond)
	if err := r.Present("lab.example.test", "tok", "keyauth"); err != nil {
		t.Fatal(err)
	}
	check := func(string, string) (bool, error) { return true, nil }
	step := "challenge lab.example.test"

	ok, err := r.PreCheck("lab.example.test", "_acme-challenge.lab.example.test.", "v", check)
	if !ok || err != nil {
		t.Fatalf("PreCheck = %v, %v", ok, err)
	}
	if store.deleted == 0 || len(store.rows) != 0 {
		t.Fatal("pending rows must be removed on timeout")
	}
	if sink.steps[step] != StepFailed {
		t.Fatalf("step = %q", sink.steps[step])
	}
	if msg := sink.lastMessage(step); !strings.Contains(msg, "manual-dns timed out") {
		t.Fatalf("message should name the manual timeout: %q", msg)
	}

	start := time.Now()
	ok, err = r.PreCheck("lab.example.test", "_acme-challenge.lab.example.test.", "v", check)
	if !ok || err != nil {
		t.Fatalf("second PreCheck = %v, %v", ok, err)
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("second PreCheck must not wait again")
	}
	if n := sink.count(step, StepFailed); n != 1 {
		t.Fatalf("StepFailed recorded %d times, want exactly 1", n)
	}

	if got, iv := mp.Timeout(); got != dns01.DefaultPropagationTimeout || iv != dns01.DefaultPollingInterval {
		t.Fatalf("provider Timeout unaffected by the router's fail-fast = %v, %v", got, iv)
	}
	if got, iv := r.Timeout(); got != failFastTimeout || iv != failFastInterval {
		t.Fatalf("router Timeout after failure = %v, %v; want %v, %v", got, iv, failFastTimeout, failFastInterval)
	}
}

// Review Focus: the router's own context being cancelled (the caller gave
// up on the issuance) must fail the current name fast, exactly like a
// manual-dns timeout, instead of leaving PreCheck's Waiter wait (and lego's
// wait.For) polling for up to the wait budget.
func TestManualCancelledContextFailsFast(t *testing.T) {
	store := &memManual{}
	ctx, cancel := context.WithCancel(context.Background())
	r, _, sink := manualRouterCtx(ctx, t, store, time.Hour)
	if err := r.Present("lab.example.test", "tok", "keyauth"); err != nil {
		t.Fatal(err)
	}
	cancel()

	check := func(string, string) (bool, error) { return true, nil }
	step := "challenge lab.example.test"

	ok, err := r.PreCheck("lab.example.test", "_acme-challenge.lab.example.test.", "v", check)
	if !ok || err != nil {
		t.Fatalf("PreCheck = %v, %v", ok, err)
	}
	if sink.steps[step] != StepFailed {
		t.Fatalf("step = %q", sink.steps[step])
	}
	if msg := sink.lastMessage(step); !strings.Contains(msg, "cancelled") {
		t.Fatalf("message should name the cancellation: %q", msg)
	}

	ok, err = r.PreCheck("lab.example.test", "_acme-challenge.lab.example.test.", "v", check)
	if !ok || err != nil {
		t.Fatalf("second PreCheck = %v, %v", ok, err)
	}
	if n := sink.count(step, StepFailed); n != 1 {
		t.Fatalf("StepFailed recorded %d times, want exactly 1", n)
	}
	if got, iv := r.Timeout(); got != failFastTimeout || iv != failFastInterval {
		t.Fatalf("router Timeout after cancellation = %v, %v; want %v, %v", got, iv, failFastTimeout, failFastInterval)
	}
}

// Review Focus: before any failure, Timeout must still be the normal
// computation (provider timeout plus the manual wait budget), not the
// fail-fast value.
func TestManualTimeoutNormalBeforeFailure(t *testing.T) {
	store := &memManual{}
	r, mp, _ := manualRouter(t, store, 30*time.Millisecond)
	if err := r.Present("lab.example.test", "tok", "keyauth"); err != nil {
		t.Fatal(err)
	}
	got, iv := r.Timeout()
	if got == failFastTimeout || iv == failFastInterval {
		t.Fatalf("Timeout must not be the fail-fast value before any failure: %v, %v", got, iv)
	}
	if got < mp.Wait {
		t.Fatalf("router timeout %v must include manual wait %v", got, mp.Wait)
	}
}

func TestManualWaitHonoursContext(t *testing.T) {
	store := &memManual{}
	mp := NewManual(store, uuid.New(), uuid.New())
	mp.Poll = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	_ = mp.Present(ctx, "a.example.test", "t", "k")
	cancel()
	if err := mp.WaitReady(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
}
