package challenge

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

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

type sinkRec struct {
	mu    sync.Mutex
	steps map[string]string
}

func (s *sinkRec) Step(name, status, _ string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.steps == nil {
		s.steps = map[string]string{}
	}
	s.steps[name] = status
}

func manualRouter(t *testing.T, store *memManual, wait time.Duration) (*Router, *ManualProvider, *sinkRec) {
	t.Helper()
	mp := NewManual(store, uuid.New(), uuid.New())
	mp.Wait, mp.Poll = wait, 5*time.Millisecond
	sink := &sinkRec{}
	r := NewRouter(context.Background(), []string{"lab.example.test"}, []Rule{rule(t, "*", mp)}, sink)
	return r, mp, sink
}

func TestManualConfirmResumes(t *testing.T) {
	store := &memManual{}
	r, _, sink := manualRouter(t, store, time.Minute)
	if err := r.Present("lab.example.test", "tok", "keyauth"); err != nil {
		t.Fatal(err)
	}
	if len(store.rows) != 1 || store.rows[0].FQDN != "_acme-challenge.lab.example.test" || store.rows[0].Value == "" {
		t.Fatalf("rows = %+v", store.rows)
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

// Review Focus: manual-dns timeout while the operator is away.
func TestManualTimeoutFailsFastAfterDeadline(t *testing.T) {
	store := &memManual{}
	r, mp, _ := manualRouter(t, store, 30*time.Millisecond)
	if err := r.Present("lab.example.test", "tok", "keyauth"); err != nil {
		t.Fatal(err)
	}
	check := func(string, string) (bool, error) { return true, nil }
	_, err := r.PreCheck("lab.example.test", "_acme-challenge.lab.example.test.", "v", check)
	if !errors.Is(err, ErrManualTimeout) {
		t.Fatalf("err = %v", err)
	}
	if store.deleted == 0 || len(store.rows) != 0 {
		t.Fatal("pending rows must be removed on timeout")
	}
	start := time.Now()
	if _, err := r.PreCheck("lab.example.test", "_acme-challenge.lab.example.test.", "v", check); !errors.Is(err, ErrManualTimeout) {
		t.Fatalf("second call err = %v", err)
	}
	if time.Since(start) > 10*time.Millisecond {
		t.Fatal("second PreCheck must not wait again")
	}
	if got, _ := r.Timeout(); got < mp.Wait {
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
