package authn

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// newTestSource builds a SettingsSource with a fake load func, bypassing
// the database. now is a swappable clock like the real constructor's.
func newTestSource(load func(ctx context.Context) (AuthSettings, error)) (*SettingsSource, *time.Time) {
	now := time.Now()
	s := &SettingsSource{ttl: 30 * time.Second, now: func() time.Time { return now }, load: load}
	return s, &now
}

// TestSettingsSourceServesStaleWhileReloading covers M3: once a value is
// cached, a second caller arriving while a reload is already in flight must
// get the stale cached value immediately rather than block on, or trigger a
// second, concurrent DB round trip.
func TestSettingsSourceServesStaleWhileReloading(t *testing.T) {
	var calls int32
	started := make(chan struct{}, 8)
	reloadEntered := make(chan struct{})
	reloadRelease := make(chan struct{})
	load := func(context.Context) (AuthSettings, error) {
		n := atomic.AddInt32(&calls, 1)
		started <- struct{}{}
		if n == 2 {
			close(reloadEntered)
			<-reloadRelease // block only the second (reload-under-test) call
		}
		st := AuthSettings{SessionTTLHours: 12}
		st.normalize()
		return st, nil
	}
	s, now := newTestSource(load)

	// Warm-up load (call 1, does not block) so the cache holds a value.
	st, err := s.Get(context.Background())
	if err != nil || st.SessionTTLHours != 12 {
		t.Fatalf("warm-up: %+v %v", st, err)
	}
	<-started

	// Expire the cache, then have one goroutine reload (call 2, blocks on
	// reloadRelease until we let it through).
	*now = now.Add(31 * time.Second)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if _, err := s.Get(context.Background()); err != nil {
			t.Errorf("reloading Get: %v", err)
		}
	}()
	<-reloadEntered // the reloading goroutine is now blocked inside load

	// A second caller, concurrent with the in-flight reload, must get the
	// stale value back immediately rather than block on, or trigger, its
	// own call to load.
	done := make(chan AuthSettings, 1)
	go func() {
		st, err := s.Get(context.Background())
		if err != nil {
			t.Errorf("stale Get: %v", err)
		}
		done <- st
	}()
	select {
	case st := <-done:
		if st.SessionTTLHours != 12 {
			t.Fatalf("expected the stale cached value, got %+v", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("second Get blocked on the in-flight reload instead of serving the stale value")
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("expected exactly 2 load calls (warm-up + one reload), got %d", n)
	}

	close(reloadRelease)
	wg.Wait()
}

// TestSettingsSourceNegativeCacheOnError covers M3: with nothing cached yet,
// a reload error is remembered for negativeCacheTTL, so a burst of callers
// during that window gets the same error without retrying the store, and a
// call after the window tries again.
func TestSettingsSourceNegativeCacheOnError(t *testing.T) {
	var calls int32
	wantErr := errors.New("store unavailable")
	load := func(context.Context) (AuthSettings, error) {
		atomic.AddInt32(&calls, 1)
		return AuthSettings{}, wantErr
	}
	s, now := newTestSource(load)

	if _, err := s.Get(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("first Get: %v", err)
	}
	if _, err := s.Get(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("second Get within negative cache: %v", err)
	}
	if n := atomic.LoadInt32(&calls); n != 1 {
		t.Fatalf("expected exactly 1 store call within the negative cache window, got %d", n)
	}

	*now = now.Add(negativeCacheTTL + time.Second)
	if _, err := s.Get(context.Background()); !errors.Is(err, wantErr) {
		t.Fatalf("Get after negative cache expiry: %v", err)
	}
	if n := atomic.LoadInt32(&calls); n != 2 {
		t.Fatalf("expected a second store call after the negative cache expired, got %d", n)
	}
}
