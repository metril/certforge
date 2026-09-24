package issuance

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/metril/certforge/internal/challenge"
)

// TestTimelineLogCap is the Review Focus for the fix-round log bound: a
// wedged or chatty provider (or a manual-dns wait spanning up to an hour of
// poll attempts) must not grow the stored log without limit.
func TestTimelineLogCap(t *testing.T) {
	tl := NewTimeline(func() time.Time { return t0 }, nil)
	line := strings.Repeat("x", 100)
	for i := 0; i < 2000; i++ { // 2000 * ~107 bytes > 200 KiB, well past the 64 KiB cap
		tl.Logf("%s", line)
	}
	_, log := tl.Snapshot()
	if len(log) > maxLogBytes+len(truncatedMarker) {
		t.Fatalf("log is %d bytes, want at most ~%d", len(log), maxLogBytes)
	}
	if !strings.HasPrefix(log, truncatedMarker) {
		t.Fatalf("log does not start with the truncation marker: %q", log[:min(len(log), 80)])
	}
	if strings.Count(log, "[log truncated]") != 1 {
		t.Fatalf("want exactly one truncation marker, log = %d bytes", len(log))
	}
	// The most recent line must survive truncation (oldest lines drop first).
	if !strings.Contains(log, line) {
		t.Fatal("newest log line was dropped instead of the oldest")
	}
}

func TestTimeline(t *testing.T) {
	now := t0
	saves := 0
	tl := NewTimeline(func() time.Time { now = now.Add(time.Second); return now }, func([]Step, string) { saves++ })
	tl.Step("caa", challenge.StepSkipped, "Phase 4")
	tl.Step("order", challenge.StepRunning, "")
	tl.Step("challenge a.example.test", challenge.StepRunning, "presenting")
	tl.Step("challenge b.example.test", challenge.StepWaitingManual, "")
	tl.Finish(challenge.StepFailed, "boom")

	steps, log := tl.Snapshot()
	got := map[string]string{}
	for _, s := range steps {
		got[s.Name] = s.Status
		if terminal(s.Status) && s.FinishedAt == nil {
			t.Errorf("%s finished without time", s.Name)
		}
	}
	want := map[string]string{"caa": "skipped", "order": "success", "challenge a.example.test": "failed", "challenge b.example.test": "failed"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q want %q", k, got[k], v)
		}
	}
	if saves < 5 || !strings.Contains(log, "presenting") {
		t.Errorf("saves=%d log=%q", saves, log)
	}
}

// Review Focus: a step that goes back to a non-terminal status (retried
// after a transient failure) must not keep its old FinishedAt.
func TestTimelineClearsFinishedAtOnRetry(t *testing.T) {
	tl := NewTimeline(func() time.Time { return t0 }, nil)
	tl.Step("order", challenge.StepFailed, "boom")
	steps, _ := tl.Snapshot()
	if steps[0].FinishedAt == nil {
		t.Fatal("failed step should have FinishedAt")
	}
	tl.Step("order", challenge.StepRunning, "retrying")
	steps, _ = tl.Snapshot()
	if steps[0].FinishedAt != nil {
		t.Fatalf("retried step still has FinishedAt: %+v", steps[0])
	}
}

// Review Focus: save must run while Step still holds the lock, so a second
// Step call (and its save) cannot start, let alone finish, until the first
// one's save has returned. Otherwise a slow save for an earlier state could
// land after a faster save for a later state and overwrite it.
func TestTimelineSaveHoldsLock(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	var saveCount int
	tl := NewTimeline(func() time.Time { return t0 }, func(steps []Step, _ string) {
		mu.Lock()
		saveCount++
		first := saveCount == 1
		mu.Unlock()
		if first {
			close(started)
			<-release
		}
	})

	go tl.Step("a", challenge.StepRunning, "")
	<-started

	done := make(chan struct{})
	go func() {
		tl.Step("b", challenge.StepRunning, "")
		close(done)
	}()

	select {
	case <-done:
		t.Fatal("second Step returned while the first save was still blocked; save must run under the lock")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	<-done
}
