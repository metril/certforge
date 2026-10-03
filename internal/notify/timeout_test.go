package notify_test

import (
	"testing"
	"time"

	"github.com/metril/certforge/internal/notify"
)

func TestScanWorkerTimeout(t *testing.T) {
	if got := (&notify.ScanWorker{}).Timeout(nil); got < 10*time.Minute {
		t.Fatalf("Timeout = %v, want >= 10m", got)
	}
}
