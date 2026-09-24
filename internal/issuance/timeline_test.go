package issuance

import (
	"strings"
	"testing"
	"time"

	"github.com/metril/certforge/internal/challenge"
)

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
