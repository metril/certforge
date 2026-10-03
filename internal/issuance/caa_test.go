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
// (no trailing dot); errs gives a per-owner error (checked first), err
// gives one returned for every lookup.
type fakeCAAResolver struct {
	records map[string][]CAARecord
	errs    map[string]error
	err     error
}

func (f fakeCAAResolver) LookupCAA(_ context.Context, fqdn string, _ []string) ([]CAARecord, error) {
	owner := strings.TrimSuffix(fqdn, ".")
	if e, ok := f.errs[owner]; ok {
		return nil, e
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.records[owner], nil
}

func TestCheckCAA(t *testing.T) {
	ids := []string{"letsencrypt.org"}

	cases := []struct {
		name       string
		names      []string
		records    map[string][]CAARecord
		errs       map[string]error
		identities []string
		lookupErr  error
		wantErr    bool
		wantDetail string // checked only when non-empty
		wantTag    string // checked only when non-empty: the fix hint's "CAA 0 <tag>"
	}{
		{
			name:  "forbidding record above the registered domain",
			names: []string{"a.example.co.uk"},
			records: map[string][]CAARecord{
				"co.uk": {{Tag: "issue", Value: "other-ca.example"}},
			},
			wantErr: true,
		},
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
		{
			// Review fix round 1: a lookup error must not make CheckCAA
			// return early as "success, let the CA check" while a later
			// name's CAA records would actually forbid issuance — the
			// error is remembered, every name is still checked, and a
			// forbidding result wins over an earlier lookup error.
			name:  "a lookup error on one name does not hide a later forbidding name",
			names: []string{"a.example.org", "b.example.net"},
			records: map[string][]CAARecord{
				"b.example.net": {{Tag: "issue", Value: "other-ca.example"}},
			},
			errs: map[string]error{
				"a.example.org": errors.New("network unreachable"),
			},
			wantErr: true,
		},
		{
			// Review fix round 1: a mixed-case issuer domain with a
			// trailing ";"-parameter still matches, case-insensitively,
			// after stripping the parameter.
			name:  "mixed-case parameterized issuer value matches",
			names: []string{"example.com"},
			records: map[string][]CAARecord{
				"example.com": {{Tag: "issue", Value: "LetsEncrypt.org; validationmethods=dns-01"}},
			},
		},
		{
			// Review fix round 1: the fix hint names the tag that was
			// actually evaluated ("issue" here, since issuewild is absent).
			name:  "mismatch fix hint names issue",
			names: []string{"example.com"},
			records: map[string][]CAARecord{
				"example.com": {{Tag: "issue", Value: "other-ca.example"}},
			},
			wantErr: true,
			wantTag: "issue",
		},
		{
			// Review fix round 1: for a wildcard name with an issuewild
			// record present, the fix hint names issuewild, not issue.
			name:  "wildcard mismatch fix hint names issuewild",
			names: []string{"*.example.com"},
			records: map[string][]CAARecord{
				"example.com": {{Tag: "issuewild", Value: "other-ca.example"}},
			},
			wantErr: true,
			wantTag: "issuewild",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := fakeCAAResolver{records: tc.records, errs: tc.errs, err: tc.lookupErr}
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
				if tc.wantTag != "" && !strings.Contains(se.Detail, "CAA 0 "+tc.wantTag+" ") {
					t.Fatalf("Detail = %q, want it to name tag %q", se.Detail, tc.wantTag)
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

// TestCheckCAAEmptyIdentitiesNoPanic: identities[0] used to be indexed
// unconditionally when building the forbidding detail — an empty
// identities slice (a caller other than caaStep, which already guards
// this) must not panic.
func TestCheckCAAEmptyIdentitiesNoPanic(t *testing.T) {
	r := fakeCAAResolver{records: map[string][]CAARecord{
		"example.com": {{Tag: "issue", Value: "letsencrypt.org"}},
	}}
	_, err := CheckCAA(context.Background(), r, []string{"example.com"}, nil, nil)
	var se *signer.Error
	if !errors.As(err, &se) {
		t.Fatalf("err = %v, want *signer.Error (no identities authorizes nothing)", err)
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

// TestDNSCAAResolverServfail: review fix round 1. A SERVFAIL (or any rcode
// other than NOERROR/NXDOMAIN) must not read as "no CAA records" — that
// would let the tree-climb walk up to a parent that could falsely forbid,
// or report "issuance allowed" with nothing actually checked. It must be
// treated as a lookup error.
func TestDNSCAAResolverServfail(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetRcode(req, dns.RcodeServerFailure)
		_ = w.WriteMsg(m)
	})}
	go func() { _ = srv.ActivateAndServe() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	r := DNSCAAResolver{}
	got, err := r.LookupCAA(context.Background(), "example.com", []string{pc.LocalAddr().String()})
	if err == nil {
		t.Fatalf("want an error for SERVFAIL, got records %+v", got)
	}
}

// TestDNSCAAResolverTCPFallback: review fix round 1. A truncated UDP answer
// must be retried over TCP against the same address, and the TCP answer's
// records returned.
func TestDNSCAAResolverTCPFallback(t *testing.T) {
	tln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := tln.Addr().String()
	tcpSrv := &dns.Server{Listener: tln, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		q := req.Question[0]
		m.Answer = append(m.Answer, &dns.CAA{Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCAA, Class: dns.ClassINET, Ttl: 60}, Flag: 0, Tag: "issue", Value: "letsencrypt.org"})
		_ = w.WriteMsg(m)
	})}
	go func() { _ = tcpSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = tcpSrv.Shutdown() })

	pc, err := net.ListenPacket("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	udpSrv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, req *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(req)
		m.Truncated = true
		_ = w.WriteMsg(m)
	})}
	go func() { _ = udpSrv.ActivateAndServe() }()
	t.Cleanup(func() { _ = udpSrv.Shutdown() })

	r := DNSCAAResolver{}
	got, err := r.LookupCAA(context.Background(), "example.com", []string{addr})
	if err != nil {
		t.Fatal(err)
	}
	want := CAARecord{Flag: 0, Tag: "issue", Value: "letsencrypt.org"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("got %+v, want [%+v]", got, want)
	}
}
