package monitor

import (
	"testing"
)

func TestCheckWorkerTimeout(t *testing.T) {
	if got := (&CheckWorker{}).Timeout(nil); got != checkTimeout {
		t.Fatalf("Timeout = %v, want %v", got, checkTimeout)
	}
}
