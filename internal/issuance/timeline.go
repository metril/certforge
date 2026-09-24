package issuance

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/metril/certforge/internal/challenge"
)

// Step is one entry of issuance_attempts.steps.
type Step struct {
	Name       string     `json:"name"`
	Status     string     `json:"status"`
	StartedAt  time.Time  `json:"startedAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
	Message    string     `json:"message,omitempty"`
}

// Timeline records the steps and log of one attempt and persists every
// change through save. It implements challenge.StepSink.
type Timeline struct {
	mu    sync.Mutex
	now   func() time.Time
	save  func(steps []Step, log string)
	steps []Step
	log   strings.Builder
}

// NewTimeline returns a Timeline; save may be nil.
func NewTimeline(now func() time.Time, save func([]Step, string)) *Timeline {
	if save == nil {
		save = func([]Step, string) {}
	}
	return &Timeline{now: now, save: save}
}

func terminal(status string) bool {
	return status == challenge.StepSuccess || status == challenge.StepFailed || status == challenge.StepSkipped
}

// Step creates or updates the named step. The first "challenge ..." step
// closes a running "order" step, because lego only calls Present once the
// order and its authorizations exist. save runs while the lock is still
// held, so two concurrent calls can never have their saves land out of
// order (a stale snapshot overwriting a newer one).
func (t *Timeline) Step(name, status, message string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now().UTC()
	if strings.HasPrefix(name, "challenge ") {
		t.setLocked("order", challenge.StepSuccess, "", now, true)
	}
	t.setLocked(name, status, message, now, false)
	if message != "" {
		fmt.Fprintf(&t.log, "%s %s [%s] %s\n", now.Format(time.RFC3339), name, status, message)
	} else {
		fmt.Fprintf(&t.log, "%s %s [%s]\n", now.Format(time.RFC3339), name, status)
	}
	steps, log := t.snapshotLocked()
	t.save(steps, log)
}

func (t *Timeline) setLocked(name, status, message string, now time.Time, onlyIfRunning bool) {
	for i := range t.steps {
		s := &t.steps[i]
		if s.Name != name {
			continue
		}
		if onlyIfRunning && s.Status != challenge.StepRunning {
			return
		}
		s.Status = status
		if message != "" {
			s.Message = message
		}
		if terminal(status) {
			s.FinishedAt = &now
		} else {
			s.FinishedAt = nil
		}
		return
	}
	if onlyIfRunning {
		return
	}
	s := Step{Name: name, Status: status, StartedAt: now, Message: message}
	if terminal(status) {
		s.FinishedAt = &now
	}
	t.steps = append(t.steps, s)
}

// Logf appends a free-form log line.
func (t *Timeline) Logf(format string, args ...any) {
	t.mu.Lock()
	defer t.mu.Unlock()
	fmt.Fprintf(&t.log, "%s %s\n", t.now().UTC().Format(time.RFC3339), fmt.Sprintf(format, args...))
	steps, log := t.snapshotLocked()
	t.save(steps, log)
}

// Finish marks every running or waiting step as status with message.
func (t *Timeline) Finish(status, message string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now().UTC()
	for i := range t.steps {
		s := &t.steps[i]
		if s.Status == challenge.StepRunning || s.Status == challenge.StepWaitingManual {
			s.Status = status
			if message != "" {
				s.Message = message
			}
			s.FinishedAt = &now
		}
	}
	steps, log := t.snapshotLocked()
	t.save(steps, log)
}

// Snapshot returns a copy of steps and the log.
func (t *Timeline) Snapshot() ([]Step, string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.snapshotLocked()
}

func (t *Timeline) snapshotLocked() ([]Step, string) {
	return append([]Step(nil), t.steps...), t.log.String()
}
