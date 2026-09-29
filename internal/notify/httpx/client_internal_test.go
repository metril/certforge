package httpx

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/miekg/dns"
)

// startDNS serves an A answer for every query, on a random UDP port on
// 127.0.0.1 (same helper shape as internal/challenge/router_test.go's own
// startDNS). Used only by TestDialRejectsLoopbackAfterResolve below.
func startDNS(t *testing.T, answer string) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		if len(req.Question) == 1 && req.Question[0].Qtype == dns.TypeA {
			rr, err := dns.NewRR(req.Question[0].Name + " 5 IN A " + answer)
			if err == nil {
				m.Answer = append(m.Answer, rr)
			}
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })
	return pc.LocalAddr().String()
}

// TestDialRejectsLoopbackAfterResolve is the end-to-end DNS-rebinding case
// (batch-1 review finding 6): "rebind.test" resolves, through a stub DNS
// server, to 127.0.0.1 — a hostname CheckURL alone has nothing to reject,
// since it never resolves anything. Do must still fail, because
// DialControl re-checks the address net.Dialer actually resolved to,
// against the very connection attempt it is about to make. The resolver
// hook (Client.dialer, unexported) exists only for this white-box test;
// production always dials with the default system resolver.
func TestDialRejectsLoopbackAfterResolve(t *testing.T) {
	dnsAddr := startDNS(t, "127.0.0.1")

	c, err := New(Options{AllowLoopback: false})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.dialer.Resolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "udp", dnsAddr)
		},
	}

	_, err = c.Do(context.Background(), http.MethodGet, "http://rebind.test/", nil, nil)
	if err == nil {
		t.Fatal("Do succeeded against a hostname that resolves to a blocked loopback address")
	}
	// Not just any error: specifically the policy's own rejection, so this
	// test cannot pass merely because nothing happens to be listening on
	// 127.0.0.1:80 in the test environment (an ordinary connection-refused
	// error would also make err non-nil, but would not prove DialControl
	// ran at all).
	if !strings.Contains(err.Error(), "not allowed") {
		t.Fatalf("error = %q, want the SSRF policy's own rejection (\"not allowed\")", err.Error())
	}
}
