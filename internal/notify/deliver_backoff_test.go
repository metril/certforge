package notify

import (
	"testing"
	"time"
)

func TestDeliverBackoffWindow(t *testing.T) {
	var total time.Duration
	for a := 1; a < deliverMaxAttempts; a++ {
		d := deliverBackoff(a)
		if d > deliverBackoffCap {
			t.Fatalf("attempt %d waits %v, over the cap", a, d)
		}
		total += d
	}
	if total < 4*time.Hour || total > 6*time.Hour {
		t.Errorf("total retry window = %v, want about 5h", total)
	}
	if deliverBackoff(1) != 30*time.Second || deliverBackoff(100) != time.Hour {
		t.Errorf("backoff ends: %v %v", deliverBackoff(1), deliverBackoff(100))
	}
}
