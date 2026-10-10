package agent

import (
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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
