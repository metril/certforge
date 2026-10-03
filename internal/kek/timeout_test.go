package kek

import (
	"testing"
)

func TestRewrapWorkerTimeoutDisabled(t *testing.T) {
	// river treats -1 as "no timeout"; the 1-minute default would cancel a long rewrap.
	if got := (&RewrapWorker{}).Timeout(nil); got != -1 {
		t.Fatalf("Timeout = %v, want -1", got)
	}
}
