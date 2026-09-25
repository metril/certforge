package authn

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	l := NewLimiter(10, 5)
	l.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("attempt %d refused", i+1)
		}
	}
	ok, wait := l.Allow("a")
	if ok || wait <= 0 || wait > 6*time.Second {
		t.Fatalf("6th: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("other key limited")
	}
	now = now.Add(6 * time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("token not refilled after 6s")
	}
	now = now.Add(11 * time.Minute)
	l.Allow("c")
	if _, ok := l.buckets["a"]; ok {
		t.Fatal("idle bucket not swept")
	}
}

func TestLimiterUnlimited(t *testing.T) {
	l := NewLimiter(0, 0)
	for i := 0; i < 100; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatal("unlimited limiter refused")
		}
	}
}

func TestLimiterReconfigure(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	l := NewLimiter(10, 5)
	l.now = func() time.Time { return now }
	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("attempt %d refused", i+1)
		}
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("6th allowed before reconfigure")
	}
	l.Reconfigure(0, 0)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("not unlimited after Reconfigure(0, 0)")
	}
	l.Reconfigure(10, 5)
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("bucket not reset to the reconfigured limit")
	}
}

// TestLimiterConcurrentAllowReconfigure exercises Allow and Reconfigure from
// many goroutines together; run with -race to catch the perMinute/burst
// read outside the lock this test was added to guard against.
func TestLimiterConcurrentAllowReconfigure(t *testing.T) {
	l := NewLimiter(1000, 1000)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			key := fmt.Sprintf("k%d", i%3)
			for j := 0; j < 200; j++ {
				l.Allow(key)
			}
		}(i)
	}
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				l.Reconfigure(1000+i, 1000+i)
			}
		}(i)
	}
	wg.Wait()
}

// TestLimiterBucketCap checks that the per-key map is bounded and that once
// full, a new key evicts the single oldest (least recently seen) entry
// rather than growing without bound.
func TestLimiterBucketCap(t *testing.T) {
	now := time.Unix(3_000_000, 0)
	l := NewLimiter(10, 5)
	l.now = func() time.Time { return now }
	const cap = 5
	saved := maxBuckets
	maxBuckets = cap
	t.Cleanup(func() { maxBuckets = saved })
	for i := 0; i < cap; i++ {
		now = now.Add(time.Second)
		l.Allow(fmt.Sprintf("k%d", i))
	}
	if len(l.buckets) != cap {
		t.Fatalf("buckets = %d, want %d", len(l.buckets), cap)
	}
	// k0 is the oldest (least recently seen); one more distinct key must
	// evict it rather than growing the map past cap.
	now = now.Add(time.Second)
	l.Allow("new")
	if len(l.buckets) != cap {
		t.Fatalf("buckets after overflow = %d, want %d", len(l.buckets), cap)
	}
	if _, ok := l.buckets["k0"]; ok {
		t.Fatal("oldest bucket k0 not evicted")
	}
	if _, ok := l.buckets["new"]; !ok {
		t.Fatal("new bucket not admitted")
	}
}

func TestLimitKey(t *testing.T) {
	if LimitKey("2001:db8::1") != LimitKey("2001:db8::2") {
		t.Fatal("IPv6 /64 not grouped")
	}
	if LimitKey("::ffff:192.0.2.1") != "192.0.2.1" || LimitKey("192.0.2.1") == LimitKey("192.0.2.2") {
		t.Fatal("IPv4 keys wrong")
	}
}
