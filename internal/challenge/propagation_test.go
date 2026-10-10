package challenge

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// startSplitDNS serves h on the same port over UDP and TCP and returns host:port.
func startSplitDNS(t *testing.T, udp, tcp dns.HandlerFunc) string {
	t.Helper()
	var pc net.PacketConn
	var ln net.Listener
	for i := 0; ; i++ {
		var err error
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			break
		}
		_ = pc.Close() // the TCP port was taken; try another UDP port
		if i >= 20 {
			t.Fatal(err)
		}
	}
	for _, s := range []*dns.Server{
		{PacketConn: pc, Handler: udp},
		{Listener: ln, Handler: tcp},
	} {
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		go func() { _ = s.ActivateAndServe() }()
		<-started
		t.Cleanup(func() { _ = s.Shutdown() })
	}
	return pc.LocalAddr().String()
}

func TestCheckTXTRetriesTruncatedOverTCP(t *testing.T) {
	answer := func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Answer = []dns.RR{&dns.TXT{Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"want"}}}
		_ = w.WriteMsg(m)
	}
	var sawEDNS atomic.Bool
	addr := startSplitDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		sawEDNS.Store(r.IsEdns0() != nil)
		m := new(dns.Msg)
		m.SetReply(r)
		m.Truncated = true
		_ = w.WriteMsg(m)
	}, answer)
	ok, err := CheckTXT(context.Background(), []string{addr}, "_acme-challenge.example.test", "want")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if !sawEDNS.Load() {
		t.Error("UDP query carried no EDNS0 OPT record")
	}
}

func TestCheckTXTDoH(t *testing.T) {
	var gotCT, gotAccept, gotMethod string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCT, gotAccept, gotMethod = r.Header.Get("Content-Type"), r.Header.Get("Accept"), r.Method
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		if err := q.Unpack(body); err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		resp := new(dns.Msg)
		resp.SetReply(q)
		resp.Answer = append(resp.Answer, &dns.TXT{Hdr: dns.RR_Header{Name: q.Question[0].Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET}, Txt: []string{"tok"}})
		wire, _ := resp.Pack()
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(wire)
	}))
	defer srv.Close()
	old := dohClient
	dohClient = srv.Client()
	t.Cleanup(func() { dohClient = old })

	ok, err := CheckTXT(context.Background(), []string{srv.URL}, "_acme-challenge.example.com", "tok")
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if gotMethod != "POST" || gotCT != "application/dns-message" || gotAccept != "application/dns-message" {
		t.Errorf("request %q %q %q", gotMethod, gotCT, gotAccept)
	}
	if ok, _ := CheckTXT(context.Background(), []string{srv.URL}, "_acme-challenge.example.com", "other"); ok {
		t.Error("mismatched value reported visible")
	}
	if _, err := CheckTXT(context.Background(), []string{"https://127.0.0.1:1/dns-query"}, "x.example.com", "tok"); err == nil {
		t.Error("expected error from unreachable DoH endpoint")
	}
}

func TestCheckTXTFailureRcodeIsError(t *testing.T) {
	addr := startSplitDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	}, func(w dns.ResponseWriter, r *dns.Msg) {})
	ok, err := CheckTXT(context.Background(), []string{addr}, "_acme-challenge.example.com", "v")
	if ok || err == nil || !strings.Contains(err.Error(), "returned REFUSED") {
		t.Fatalf("ok=%v err=%v", ok, err)
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		q := new(dns.Msg)
		_ = q.Unpack(body)
		m := new(dns.Msg)
		m.SetRcode(q, dns.RcodeServerFailure)
		wire, _ := m.Pack()
		_, _ = w.Write(wire)
	}))
	defer srv.Close()
	old := dohClient
	dohClient = srv.Client()
	t.Cleanup(func() { dohClient = old })
	if _, err := CheckTXT(context.Background(), []string{srv.URL}, "x.example.com", "v"); err == nil || !strings.Contains(err.Error(), "SERVFAIL") {
		t.Fatalf("doh err=%v", err)
	}
}

func TestDoHRefusesRedirects(t *testing.T) {
	if err := dohClient.CheckRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("CheckRedirect = %v", err)
	}
}

func TestRouterHintRefusedFromConfiguredResolvers(t *testing.T) {
	setSettle(t, 0)
	addr := startSplitDNS(t, func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(r, dns.RcodeRefused)
		_ = w.WriteMsg(m)
	}, func(w dns.ResponseWriter, r *dns.Msg) {})
	ru := rule(t, "example.com", &recProvider{})
	ru.Resolvers = []string{addr}
	r := NewRouter(context.Background(), []string{"example.com"}, []Rule{ru}, nil)
	_, _ = r.PreCheck("example.com", "_acme-challenge.example.com.", "v", nil)
	if h := r.Hint(errors.New("x")); !strings.Contains(h, "intercept DNS") {
		t.Fatalf("hint = %q", h)
	}
}
