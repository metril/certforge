package challenge

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// CheckTXT reports whether every resolver answers value among the TXT records
// at fqdn. It replaces lego's propagation check when a rule, the defaults or
// the CA name resolvers, because lego v4's dns01.AddRecursiveNameservers sets
// a package-global and would leak between concurrent issuances.
func CheckTXT(ctx context.Context, resolvers []string, fqdn, value string) (bool, error) {
	c := &dns.Client{Timeout: 5 * time.Second}
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
	m.RecursionDesired = true
	for _, r := range resolvers {
		addr := r
		if _, _, err := net.SplitHostPort(r); err != nil {
			addr = net.JoinHostPort(r, "53")
		}
		in, _, err := c.ExchangeContext(ctx, m, addr)
		if err != nil {
			return false, fmt.Errorf("query %s at %s: %w", fqdn, addr, err)
		}
		found := false
		for _, rr := range in.Answer {
			if t, ok := rr.(*dns.TXT); ok && strings.Join(t.Txt, "") == value {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}
	return true, nil
}
