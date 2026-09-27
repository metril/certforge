package issuance

import (
	"testing"
	"time"
)

// TestARIPollWorkerTimeout is fix round 1's review finding: with no Timeout
// override, river's 1-minute default would cancel a run of hundreds of
// sequential ARI fetches partway through.
func TestARIPollWorkerTimeout(t *testing.T) {
	w := &ARIPollWorker{}
	if got := w.Timeout(nil); got != 30*time.Minute {
		t.Fatalf("Timeout() = %v, want 30m", got)
	}
}
