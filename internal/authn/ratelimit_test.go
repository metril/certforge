package authn

import (
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

func TestLimitKey(t *testing.T) {
	if LimitKey("2001:db8::1") != LimitKey("2001:db8::2") {
		t.Fatal("IPv6 /64 not grouped")
	}
	if LimitKey("::ffff:192.0.2.1") != "192.0.2.1" || LimitKey("192.0.2.1") == LimitKey("192.0.2.2") {
		t.Fatal("IPv4 keys wrong")
	}
}
