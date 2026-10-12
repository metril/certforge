package httpx

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestParsePeekTarget(t *testing.T) {
	ok := map[string][2]string{"https://a.example": {"a.example", "443"}, "a.example:8443": {"a.example", "8443"},
		"a.example": {"a.example", "443"}, "https://[::1]:9": {"::1", "9"}, "[::1]": {"::1", "443"}}
	for in, want := range ok {
		h, p, err := ParsePeekTarget(in)
		if err != nil || h != want[0] || p != want[1] {
			t.Errorf("%s: %s %s %v", in, h, p, err)
		}
	}
	for _, in := range []string{"", "http://a", "https://u@a", "a/b", "ftp://a"} {
		if _, _, err := ParsePeekTarget(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}

func TestPeekDialPolicy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	host, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	if _, _, err := Peek(context.Background(), host, port, "", false); err == nil {
		t.Fatal("loopback dial allowed")
	}
	chain, verified, err := Peek(context.Background(), host, port, "", true)
	if err != nil || len(chain) != 1 || verified {
		t.Fatalf("%d %v %v", len(chain), verified, err)
	}
}
