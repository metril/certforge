package issuance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"

	"github.com/metril/certforge/internal/signer"
)

// caaCritical is the CAA critical flag (RFC 8659 §4): a record with an
// unrecognised tag and this bit set forbids issuance outright.
const caaCritical = 0x80

// CAARecord is one CAA resource record.
type CAARecord struct {
	Flag  uint8
	Tag   string
	Value string
}

// CAAResolver looks up the CAA record set at fqdn using servers (host, or
// host:port; port 53 is assumed when absent). Implementations do not follow
// the RFC 8659 tree-climbing algorithm themselves — CheckCAA does that by
// calling LookupCAA once per label.
type CAAResolver interface {
	LookupCAA(ctx context.Context, fqdn string, servers []string) ([]CAARecord, error)
}

// DNSCAAResolver looks up CAA records directly over UDP via miekg/dns,
// retrying over TCP when the UDP answer is truncated. Empty servers falls
// back to the system resolver configuration in /etc/resolv.conf.
type DNSCAAResolver struct{}

// dnsTimeout bounds a single CAA query (UDP or the TCP retry).
const dnsTimeout = 5 * time.Second

// LookupCAA implements CAAResolver.
func (DNSCAAResolver) LookupCAA(ctx context.Context, fqdn string, servers []string) ([]CAARecord, error) {
	addrs, err := effectiveDNSServers(servers)
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeCAA)
	m.RecursionDesired = true
	udp := &dns.Client{Timeout: dnsTimeout}
	tcp := &dns.Client{Net: "tcp", Timeout: dnsTimeout}
	var lastErr error
	for _, addr := range addrs {
		in, _, err := udp.ExchangeContext(ctx, m, addr)
		if err == nil && in.Truncated {
			in, _, err = tcp.ExchangeContext(ctx, m, addr)
		}
		if err != nil {
			lastErr = err
			continue
		}
		return caaFromAnswer(in.Answer), nil
	}
	return nil, lastErr
}

// caaFromAnswer picks out the CAA records from a DNS answer section,
// ignoring anything else (a CNAME the resolver followed, for example).
func caaFromAnswer(rrs []dns.RR) []CAARecord {
	var out []CAARecord
	for _, rr := range rrs {
		if c, ok := rr.(*dns.CAA); ok {
			out = append(out, CAARecord{Flag: c.Flag, Tag: c.Tag, Value: c.Value})
		}
	}
	return out
}

// effectiveDNSServers normalises servers to host:port form, or reads
// /etc/resolv.conf when servers is empty.
func effectiveDNSServers(servers []string) ([]string, error) {
	if len(servers) == 0 {
		cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil {
			return nil, fmt.Errorf("read /etc/resolv.conf: %w", err)
		}
		out := make([]string, 0, len(cfg.Servers))
		for _, s := range cfg.Servers {
			out = append(out, net.JoinHostPort(s, cfg.Port))
		}
		if len(out) == 0 {
			return nil, errors.New("/etc/resolv.conf lists no nameservers")
		}
		return out, nil
	}
	out := make([]string, len(servers))
	for i, s := range servers {
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		out[i] = s
	}
	return out, nil
}

// CheckCAA runs the CAA pre-check for names against identities (the CA
// directory's published caaIdentities) through r over servers. It returns a
// human detail for the "success" outcomes below (including one that could
// not be fully evaluated — the CA re-checks CAA itself during the real
// order regardless) and only returns an error when a name's CAA records
// affirmatively forbid issuance by this CA.
//
// For each name: strip a leading "*." and climb labels from the resulting
// domain up to and including its registered domain (publicsuffix.
// EffectiveTLDPlusOne), stopping at the first label with a non-empty CAA
// record set (RFC 8659 §5.3). No record set anywhere in that climb means
// CAA does not restrict the name, and the next name is checked. A lookup
// error at any label aborts the whole check (not just that name) with a
// "success" detail, since the CA will still evaluate CAA itself.
func CheckCAA(ctx context.Context, r CAAResolver, names []string, identities []string, servers []string) (string, error) {
	for _, name := range names {
		wildcard := strings.HasPrefix(name, "*.")
		base := strings.TrimPrefix(name, "*.")
		owner, records, err := caaLookupChain(ctx, r, base, servers)
		if err != nil {
			return fmt.Sprintf("CAA lookup failed (%v); the CA will check", err), nil
		}
		if len(records) == 0 {
			continue
		}
		if err := evaluateCAA(owner, records, wildcard, identities); err != nil {
			return "", err
		}
	}
	return "CAA checked; issuance allowed", nil
}

// caaLookupChain climbs labels from name up to and including its registered
// domain, returning the first non-empty CAA record set found (and the owner
// name it was found at), or no records when every label up to and
// including the registered domain came back empty.
func caaLookupChain(ctx context.Context, r CAAResolver, name string, servers []string) (owner string, records []CAARecord, err error) {
	registered, psErr := publicsuffix.EffectiveTLDPlusOne(name)
	if psErr != nil {
		registered = name
	}
	owner = name
	for {
		recs, err := r.LookupCAA(ctx, owner, servers)
		if err != nil {
			return "", nil, err
		}
		if len(recs) > 0 {
			return owner, recs, nil
		}
		if strings.EqualFold(owner, registered) {
			return owner, nil, nil
		}
		i := strings.IndexByte(owner, '.')
		if i < 0 {
			return owner, nil, nil
		}
		owner = owner[i+1:]
	}
}

// evaluateCAA applies records (the non-empty set found at owner) to decide
// whether this CA may issue for a name at owner, wild reporting whether
// that name was a wildcard (relevant tag "issuewild" over "issue").
func evaluateCAA(owner string, records []CAARecord, wildcard bool, identities []string) error {
	// An unrecognised tag with the critical flag set forbids issuance
	// outright (RFC 8659 §4), regardless of what any issue/issuewild record
	// says.
	for _, rec := range records {
		if rec.Flag&caaCritical == 0 {
			continue
		}
		switch strings.ToLower(rec.Tag) {
		case "issue", "issuewild", "iodef":
		default:
			return caaForbidden(owner, records, identities)
		}
	}

	tag := "issue"
	if wildcard {
		for _, rec := range records {
			if strings.EqualFold(rec.Tag, "issuewild") {
				tag = "issuewild"
				break
			}
		}
	}
	var relevant []CAARecord
	for _, rec := range records {
		if strings.EqualFold(rec.Tag, tag) {
			relevant = append(relevant, rec)
		}
	}
	if len(relevant) == 0 {
		// No property of the relevant tag: nothing restricts this name.
		return nil
	}
	for _, rec := range relevant {
		v := rec.Value
		if i := strings.IndexByte(v, ';'); i >= 0 {
			v = v[:i]
		}
		v = strings.TrimSpace(v)
		if v == "" {
			continue // an empty issuer domain never matches; it forbids
		}
		for _, id := range identities {
			if strings.EqualFold(v, id) {
				return nil
			}
		}
	}
	return caaForbidden(owner, relevant, identities)
}

// caaForbidden builds the *signer.Error recorded on the attempt: the ACME
// CAA problem type and the operator-facing fix.
func caaForbidden(owner string, allow []CAARecord, identities []string) error {
	vals := make([]string, len(allow))
	for i, rec := range allow {
		vals[i] = rec.Value
	}
	detail := fmt.Sprintf("CAA at %s allows %s; the CA identifies as %s. Add: %s CAA 0 issue %q",
		owner, strings.Join(vals, ", "), strings.Join(identities, ", "), owner, identities[0])
	return &signer.Error{Type: "urn:ietf:params:acme:error:caa", Detail: detail}
}
