package backup

import (
	"testing"
	"time"
)

func TestScheduleWorkerTimeout(t *testing.T) {
	if got := (&ScheduleWorker{}).Timeout(nil); got != time.Hour {
		t.Fatalf("Timeout = %v, want 1h", got)
	}
}
