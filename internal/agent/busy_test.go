package agent

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/agentproto"
)

type busyRT struct{ calls, busy int }

func (b *busyRT) RoundTrip(*http.Request) (*http.Response, error) {
	b.calls++
	if b.calls <= b.busy {
		return nil, errBusy
	}
	return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`{}`))}, nil
}

func TestDoRetriesBusy(t *testing.T) {
	old := busyBackoff
	busyBackoff = time.Millisecond
	t.Cleanup(func() { busyBackoff = old })
	rt := &busyRT{busy: 2}
	c := &Client{hc: &http.Client{Transport: rt}, base: "http://x"}
	if err := c.do(t.Context(), http.MethodPost, "/p", map[string]int{"a": 1}, nil); err != nil {
		t.Fatal(err)
	}
	if rt.calls != 3 {
		t.Fatalf("calls %d", rt.calls)
	}
	rt = &busyRT{busy: 99}
	c.hc = &http.Client{Transport: rt}
	if err := c.do(t.Context(), http.MethodGet, "/p", nil, nil); err == nil || rt.calls != busyRetries+1 {
		t.Fatalf("must give up after %d retries: %v, %d calls", busyRetries, err, rt.calls)
	}
}

func TestHandshakeBusyIsRetried(t *testing.T) {
	old := busyBackoff
	busyBackoff = time.Millisecond
	t.Cleanup(func() { busyBackoff = old })
	f, cl := enrolledClient(t)
	f.proto.mu.Lock()
	f.proto.busyHandshakes = 2
	f.proto.mu.Unlock()
	if _, err := cl.Assignments(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.proto.mu.Lock()
	defer f.proto.mu.Unlock()
	if f.proto.busyHandshakes != 0 || f.proto.handshakes != 1 {
		t.Fatalf("busy left %d, handshakes %d", f.proto.busyHandshakes, f.proto.handshakes)
	}
}

func TestFailedReconcileIsRetried(t *testing.T) {
	old := reconcileRetry
	reconcileRetry = 20 * time.Millisecond
	t.Cleanup(func() { reconcileRetry = old })
	f := newFakeServer(t)
	a := testAgent(t, f)
	f.with(func() {
		f.assignFail = 1
		f.onWS = func(ctx context.Context, c *fakeWS) {
			b, _ := agentproto.Marshal(agentproto.Sync{})
			_ = c.Write(ctx, websocket.MessageText, b)
			<-ctx.Done()
		}
	})
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	go func() { _ = a.session(ctx, nil) }()
	for ctx.Err() == nil {
		var hits int
		f.with(func() { hits = f.assignHits })
		if hits >= 2 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the failed reconcile was not retried")
}
