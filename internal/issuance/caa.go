package issuance

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"

	"github.com/metril/certforge/internal/challenge"
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
		// Rcode must be checked: an unchecked SERVFAIL (or any other
		// failure rcode) has an empty Answer section, which would
		// otherwise read as "no CAA records here" — the tree-climb would
		// wrongly climb to a parent that could falsely forbid, or the
		// whole check would wrongly report "issuance allowed" with
		// nothing actually checked. NOERROR and NXDOMAIN both carry a
		// (possibly empty) valid answer and are not errors.
		switch in.Rcode {
		case dns.RcodeSuccess, dns.RcodeNameError:
			return caaFromAnswer(in.Answer), nil
		case dns.RcodeServerFailure:
			lastErr = fmt.Errorf("%s: SERVFAIL", addr)
		default:
			lastErr = fmt.Errorf("%s: %s", addr, dns.RcodeToString[in.Rcode])
		}
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
// DoH (https://) entries are skipped, falling back to the system resolvers
// when nothing else remains: CAA lookups are advisory (the CA re-checks).
func effectiveDNSServers(servers []string) ([]string, error) {
	plain := make([]string, 0, len(servers))
	for _, s := range servers {
		if !challenge.IsDoH(s) {
			plain = append(plain, s)
		}
	}
	servers = plain
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
// domain all the way to the TLD, stopping at the first label with a non-empty CAA
// record set (RFC 8659 §5.3). No record set anywhere in that climb means
// CAA does not restrict the name, and the next name is checked. A lookup
// error at one name is remembered but does not stop the rest of names from
// being checked, so a later name's forbidding record set still fails the
// check; only once every name has been considered does an outstanding
// lookup error fall back to a "success" detail, since the CA will still
// evaluate CAA itself.
func CheckCAA(ctx context.Context, r CAAResolver, names []string, identities []string, servers []string) (string, error) {
	// Resolve the server list once: normalising an already-normalised list is
	// a no-op, so /etc/resolv.conf is read once per run, not once per lookup.
	// On failure keep servers as given; each lookup then reports the same
	// error itself, as it always did.
	if eff, err := effectiveDNSServers(servers); err == nil {
		servers = eff
	}
	cr := &cachedCAAResolver{r: r, cache: map[string]*caaLookup{}}

	// Look the chains up in parallel (shared parent labels hit the cache and
	// are queried once), then evaluate strictly in input order so the first
	// forbidding name wins and the first lookup error is the one remembered.
	type chain struct {
		owner   string
		records []CAARecord
		err     error
	}
	chains := make([]chain, len(names))
	var g errgroup.Group
	g.SetLimit(caaParallelism)
	for i, name := range names {
		g.Go(func() error {
			c := &chains[i]
			c.owner, c.records, c.err = caaLookupChain(ctx, cr, strings.TrimPrefix(name, "*."), servers)
			return nil
		})
	}
	_ = g.Wait()

	var lookupErr error
	for i, name := range names {
		c := chains[i]
		if c.err != nil {
			if lookupErr == nil {
				lookupErr = c.err
			}
			continue
		}
		if len(c.records) == 0 {
			continue
		}
		if err := evaluateCAA(c.owner, c.records, strings.HasPrefix(name, "*."), identities); err != nil {
			return "", err
		}
	}
	if lookupErr != nil {
		return fmt.Sprintf("CAA lookup failed (%v); the CA will check", lookupErr), nil
	}
	return "CAA checked; issuance allowed", nil
}

// caaParallelism bounds how many names CheckCAA climbs at once.
const caaParallelism = 8

// cachedCAAResolver memoises one CheckCAA run's lookups by label, so names
// sharing a parent (example.com for a.example.com and b.example.com) query
// it once. Concurrent callers of the same label wait on its single lookup.
type cachedCAAResolver struct {
	r     CAAResolver
	mu    sync.Mutex
	cache map[string]*caaLookup
}

type caaLookup struct {
	once    sync.Once
	records []CAARecord
	err     error
}

func (c *cachedCAAResolver) LookupCAA(ctx context.Context, fqdn string, servers []string) ([]CAARecord, error) {
	c.mu.Lock()
	l, ok := c.cache[fqdn]
	if !ok {
		l = &caaLookup{}
		c.cache[fqdn] = l
	}
	c.mu.Unlock()
	l.once.Do(func() { l.records, l.err = c.r.LookupCAA(ctx, fqdn, servers) })
	return l.records, l.err
}

// caaLookupChain climbs labels from name up to its last label (the TLD, per
// RFC 8659 §5.3), returning the first non-empty CAA record set found (and
// the owner name it was found at), or no records when every label came back
// empty. An IP literal is looked up once and never climbed.
func caaLookupChain(ctx context.Context, r CAAResolver, name string, servers []string) (owner string, records []CAARecord, err error) {
	owner = name
	ip := net.ParseIP(name) != nil
	for {
		recs, err := r.LookupCAA(ctx, owner, servers)
		if err != nil {
			return "", nil, err
		}
		if len(recs) > 0 {
			return owner, recs, nil
		}
		i := strings.IndexByte(owner, '.')
		if ip || i < 0 {
			return owner, nil, nil
		}
		owner = owner[i+1:]
	}
}

// evaluateCAA applies records (the non-empty set found at owner) to decide
// whether this CA may issue for a name at owner, wildcard reporting
// whether that name was a wildcard (relevant tag "issuewild" over "issue").
func evaluateCAA(owner string, records []CAARecord, wildcard bool, identities []string) error {
	tag := "issue"
	if wildcard {
		for _, rec := range records {
			if strings.EqualFold(rec.Tag, "issuewild") {
				tag = "issuewild"
				break
			}
		}
	}

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
			return caaForbidden(owner, tag, records, identities)
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
	return caaForbidden(owner, tag, relevant, identities)
}

// caaForbidden builds the *signer.Error recorded on the attempt: the ACME
// CAA problem type and the operator-facing fix, naming tag ("issue" or
// "issuewild", whichever evaluateCAA actually evaluated) so the suggested
// record matches what the name needs. identities is normally non-empty
// (caaStep never reaches here otherwise), but CheckCAA is exported and a
// direct caller passing none must not panic indexing identities[0].
func caaForbidden(owner, tag string, allow []CAARecord, identities []string) error {
	vals := make([]string, len(allow))
	for i, rec := range allow {
		vals[i] = rec.Value
	}
	add := "<no caaIdentities published>"
	if len(identities) > 0 {
		add = identities[0]
	}
	detail := fmt.Sprintf("CAA at %s allows %s; the CA identifies as %s. Add: %s CAA 0 %s %q",
		owner, strings.Join(vals, ", "), strings.Join(identities, ", "), owner, tag, add)
	return &signer.Error{Type: "urn:ietf:params:acme:error:caa", Detail: detail}
}
