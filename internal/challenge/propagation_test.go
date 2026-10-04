package challenge

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/miekg/dns"
)

// startSplitDNS serves h on the same port over UDP and TCP and returns host:port.
func startSplitDNS(t *testing.T, udp, tcp dns.HandlerFunc) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", pc.LocalAddr().String())
	if err != nil {
		_ = pc.Close()
		t.Fatal(err)
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
