package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHealthcheck(t *testing.T) {
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/readyz" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.WriteHeader(status)
	}))
	defer srv.Close()
	t.Setenv("CF_LISTEN_HTTP", srv.Listener.Addr().String())
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"healthcheck"}, &out, &errOut); code != 0 {
		t.Fatalf("healthy code %d %s", code, errOut.String())
	}
	status = http.StatusServiceUnavailable
	if code := run(context.Background(), []string{"healthcheck"}, &out, &errOut); code != 1 {
		t.Fatalf("unhealthy code %d", code)
	}
}
