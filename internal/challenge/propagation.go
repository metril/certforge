package challenge

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
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
	m.SetEdns0(4096, false)
	for _, r := range resolvers {
		if IsDoH(r) {
			in, err := queryDoH(ctx, r, m)
			if err != nil {
				return false, fmt.Errorf("query %s at %s: %w", fqdn, r, err)
			}
			if !hasTXT(in, value) {
				return false, nil
			}
			continue
		}
		addr := r
		if _, _, err := net.SplitHostPort(r); err != nil {
			addr = net.JoinHostPort(r, "53")
		}
		in, _, err := c.ExchangeContext(ctx, m, addr)
		if err == nil && in.Truncated {
			in, _, err = (&dns.Client{Net: "tcp", Timeout: 5 * time.Second}).ExchangeContext(ctx, m, addr)
		}
		if err != nil {
			return false, fmt.Errorf("query %s at %s: %w", fqdn, addr, err)
		}
		if !hasTXT(in, value) {
			return false, nil
		}
	}
	return true, nil
}

func hasTXT(in *dns.Msg, value string) bool {
	for _, rr := range in.Answer {
		if t, ok := rr.(*dns.TXT); ok && strings.Join(t.Txt, "") == value {
			return true
		}
	}
	return false
}

// IsDoH reports whether a resolver entry is a DNS-over-HTTPS endpoint URL.
func IsDoH(r string) bool { return strings.HasPrefix(strings.ToLower(r), "https://") }

// ValidDoHURL reports whether r is a well-formed https URL with a host.
func ValidDoHURL(r string) bool {
	u, err := url.Parse(r)
	return err == nil && u.Scheme == "https" && u.Host != "" && !strings.ContainsAny(r, " ")
}

var dohClient = &http.Client{Timeout: 5 * time.Second}

// queryDoH sends m to a DoH endpoint per RFC 8484 (POST, wire format).
func queryDoH(ctx context.Context, endpoint string, m *dns.Msg) (*dns.Msg, error) {
	q := m.Copy()
	q.Id = 0 // RFC 8484 §4.1: cache-friendly
	wire, err := q.Pack()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := dohClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return nil, err
	}
	in := new(dns.Msg)
	if err := in.Unpack(body); err != nil {
		return nil, err
	}
	return in, nil
}

// CheckTXTAuthoritative reports whether every authoritative nameserver of
// fqdn's zone answers value among its TXT records, asking each one directly
// (no recursion), like lego's default propagation check. lego v4 exposes no
// public entry point for that check, so this mirrors it using the system
// resolvers to find the zone and its nameservers.
func CheckTXTAuthoritative(ctx context.Context, fqdn, value string) (bool, error) {
	fqdn = dns.Fqdn(fqdn)
	zone, err := dns01.FindZoneByFqdn(fqdn)
	if err != nil {
		return false, err
	}
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return false, fmt.Errorf("read /etc/resolv.conf: %w", err)
	}
	var nss []string
	for _, s := range cfg.Servers {
		nss = append(nss, net.JoinHostPort(s, cfg.Port))
	}
	nsq := new(dns.Msg)
	nsq.SetQuestion(zone, dns.TypeNS)
	nsq.RecursionDesired = true
	var nsResp *dns.Msg
	for _, a := range nss {
		if nsResp, _, err = (&dns.Client{Timeout: 5 * time.Second}).ExchangeContext(ctx, nsq, a); err == nil {
			break
		}
	}
	if nsResp == nil {
		return false, fmt.Errorf("look up nameservers of %s: %w", zone, err)
	}
	var hosts []string
	for _, rr := range nsResp.Answer {
		if n, ok := rr.(*dns.NS); ok {
			hosts = append(hosts, n.Ns)
		}
	}
	if len(hosts) == 0 {
		return false, fmt.Errorf("no nameservers found for %s", zone)
	}
	q := new(dns.Msg)
	q.SetQuestion(fqdn, dns.TypeTXT)
	for _, h := range hosts {
		addr := net.JoinHostPort(strings.TrimSuffix(h, "."), "53")
		in, _, err := (&dns.Client{Timeout: 5 * time.Second}).ExchangeContext(ctx, q, addr)
		if err == nil && in.Truncated {
			in, _, err = (&dns.Client{Net: "tcp", Timeout: 5 * time.Second}).ExchangeContext(ctx, q, addr)
		}
		if err != nil {
			return false, fmt.Errorf("query %s at %s: %w", fqdn, addr, err)
		}
		if in.Rcode != dns.RcodeSuccess && in.Rcode != dns.RcodeNameError {
			return false, fmt.Errorf("authoritative nameserver %s returned %s", addr, dns.RcodeToString[in.Rcode])
		}
		if !hasTXT(in, value) {
			return false, nil
		}
	}
	return true, nil
}
