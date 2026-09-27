package issuance

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/metril/certforge/internal/signer"
)

// fakeCAAResolver answers LookupCAA from a fixed map keyed by owner name
// (no trailing dot), or returns err when set.
type fakeCAAResolver struct {
	records map[string][]CAARecord
	err     error
}

func (f fakeCAAResolver) LookupCAA(_ context.Context, fqdn string, _ []string) ([]CAARecord, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.records[strings.TrimSuffix(fqdn, ".")], nil
}

func TestCheckCAA(t *testing.T) {
	ids := []string{"letsencrypt.org"}

	cases := []struct {
		name       string
		names      []string
		records    map[string][]CAARecord
		identities []string
		lookupErr  error
		wantErr    bool
		wantDetail string // checked only when non-empty
	}{
		{
			name:  "no records",
			names: []string{"example.com"},
		},
		{
			name:  "issue match",
			names: []string{"example.com"},
			records: map[string][]CAARecord{
				"example.com": {{Tag: "issue", Value: "letsencrypt.org"}},
			},
		},
		{
			name:  "mismatch",
			names: []string{"example.com"},
			records: map[string][]CAARecord{
				"example.com": {{Tag: "issue", Value: "other-ca.example"}},
			},
			wantErr: true,
		},
		{
			name:  "wildcard uses issuewild",
			names: []string{"*.example.com"},
			records: map[string][]CAARecord{
				"example.com": {
					{Tag: "issue", Value: "other-ca.example"},
					{Tag: "issuewild", Value: "letsencrypt.org"},
				},
			},
		},
		{
			name:  "wildcard falls back to issue when issuewild absent",
			names: []string{"*.example.com"},
			records: map[string][]CAARecord{
				"example.com": {{Tag: "issue", Value: "other-ca.example"}},
			},
			wantErr: true,
		},
		{
			name:  "semicolon-only value forbids",
			names: []string{"example.com"},
			records: map[string][]CAARecord{
				"example.com": {{Tag: "issue", Value: ";"}},
			},
			wantErr: true,
		},
		{
			name:  "climbing stops at the first non-empty set",
			names: []string{"lab.example.com"},
			records: map[string][]CAARecord{
				"example.com": {{Tag: "issue", Value: "other-ca.example"}},
			},
			wantErr: true, // lab.example.com is empty, example.com forbids
		},
		{
			name:  "climbing stops at the registered domain",
			names: []string{"foo.example.co.uk"},
			records: map[string][]CAARecord{
				// co.uk would forbid, but climbing must never reach it.
				"co.uk": {{Tag: "issue", Value: "other-ca.example"}},
			},
		},
		{
			name:       "lookup error succeeds and lets the CA check",
			names:      []string{"example.com"},
			lookupErr:  errors.New("network unreachable"),
			wantDetail: "CAA lookup failed (network unreachable); the CA will check",
		},
		{
			name:  "critical unknown tag forbids",
			names: []string{"example.com"},
			records: map[string][]CAARecord{
				"example.com": {
					{Tag: "issue", Value: "letsencrypt.org"},
					{Tag: "someunknowntag", Value: "x", Flag: caaCritical},
				},
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fakeCAAResolver{records: tc.records, err: tc.lookupErr}
			identities := tc.identities
			if identities == nil {
				identities = ids
			}
			detail, err := CheckCAA(context.Background(), r, tc.names, identities, nil)
			if tc.wantErr {
				var se *signer.Error
				if !errors.As(err, &se) {
					t.Fatalf("err = %v, want *signer.Error", err)
				}
				if se.Type != "urn:ietf:params:acme:error:caa" {
					t.Fatalf("Type = %q, want the caa problem type", se.Type)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantDetail != "" && detail != tc.wantDetail {
				t.Fatalf("detail = %q, want %q", detail, tc.wantDetail)
			}
		})
	}
}

// TestDNSCAAResolver serves CAA (and an unrelated CNAME) records from an
// in-process dns.Server, matching the pattern router_test.go's startDNS
// uses for TXT: a real UDP round trip through miekg/dns.
func TestDNSCAAResolver(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		if q.Name == "example.com." {
			m.Answer = append(m.Answer,
				&dns.CNAME{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60}, Target: "example.net."},
				&dns.CAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 60}, Flag: 0, Tag: "issue", Value: "letsencrypt.org"},
			)
		}
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	r := DNSCAAResolver{}
	got, err := r.LookupCAA(context.Background(), "example.com", []string{pc.LocalAddr().String()})
	if err != nil {
		t.Fatal(err)
	}
	want := []CAARecord{{Flag: 0, Tag: "issue", Value: "letsencrypt.org"}}
	if len(got) != 1 || got[0] != want[0] {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}
