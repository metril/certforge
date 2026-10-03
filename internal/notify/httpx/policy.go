package httpx

import (
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
)

// blockedMetadata are the cloud-metadata addresses that stay blocked even
// with allowLoopback (pre-flight ruling; Deviations R3): a webhook or
// monitor host reaching either would hand out instance credentials
// regardless of whether loopback/private targets are otherwise allowed.
var blockedMetadata = []netip.Addr{
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("fd00:ec2::254"),
}

// CheckURL validates a channel or monitor URL at create/update time and
// again immediately before a request is sent (Client.Do): the scheme must
// be http or https, the URL must carry a host and no userinfo (a
// credential in the URL itself could leak via a redirect target or a
// logged URL), and the host is classified the same way CheckHost
// classifies a literal IP or "localhost" (contract: "applies the same
// classification to literal IPs, IPv4-mapped included, and localhost").
// allowLoopback is the "notifications" settings section's
// allowLoopbackUrls (or a monitor's own org policy at check time).
func CheckURL(raw string, allowLoopback bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("httpx: invalid url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("httpx: url scheme must be http or https")
	}
	if u.User != nil {
		return fmt.Errorf("httpx: url must not contain userinfo")
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("httpx: url must have a host")
	}
	return CheckHost(host, allowLoopback)
}

// CheckHost validates a bare host (a hostname, or a literal IPv4/IPv6
// address, IPv4-mapped included) the way CheckURL validates a URL's host
// component. A real hostname (anything that is not a literal IP and not
// "localhost") is always allowed here: DNS-rebinding protection against a
// hostname that later resolves to a blocked address is DialControl's job,
// applied again at actual dial time (contract: "the URL policy runs at
// create/update and again at dial time"). Used directly by monitors
// (Deviations R5: "monitor hosts follow the R3 loopback/link-local
// policy"), which dial a bare host:port with no URL of their own.
func CheckHost(host string, allowLoopback bool) error {
	if host == "" {
		return fmt.Errorf("httpx: empty host")
	}
	if strings.EqualFold(host, "localhost") {
		if allowLoopback {
			return nil
		}
		return fmt.Errorf("httpx: host %q is not allowed", host)
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		if !classify(addr, allowLoopback) {
			return fmt.Errorf("httpx: host %q is not allowed", host)
		}
	}
	return nil
}

// classify reports whether addr may be dialed under allowLoopback.
// Unmap() first so an IPv4-mapped IPv6 literal (::ffff:127.0.0.1) is
// classified by its embedded IPv4 address, not as an ordinary global IPv6
// one (contract: "Unmap()s the address first"). The metadata addresses are
// checked before anything else and are never admitted, even when
// allowLoopback would otherwise re-admit their /16 or their prefix.
func classify(addr netip.Addr, allowLoopback bool) bool {
	addr = embeddedIPv4(addr.Unmap())
	for _, blocked := range blockedMetadata {
		if addr == blocked {
			return false
		}
	}
	if addr.IsUnspecified() || addr.IsMulticast() {
		return false
	}
	if addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsLinkLocalMulticast() {
		return allowLoopback
	}
	return true
}

var (
	nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")
	sixToFour   = netip.MustParsePrefix("2002::/16")
)

// embeddedIPv4 returns the IPv4 address a NAT64 (64:ff9b::/96) or 6to4
// (2002::/16) IPv6 address encodes, so a blocked IPv4 target cannot be
// reached through its IPv6 translation; any other address is returned as is.
func embeddedIPv4(addr netip.Addr) netip.Addr {
	if !addr.Is6() {
		return addr
	}
	b := addr.As16()
	switch {
	case nat64Prefix.Contains(addr):
		return netip.AddrFrom4([4]byte(b[12:16]))
	case sixToFour.Contains(addr):
		return netip.AddrFrom4([4]byte(b[2:6]))
	}
	return addr
}

// DialControl returns a net.Dialer.Control function that re-applies the
// same host policy CheckURL/CheckHost apply at create/update time, but
// against the address Go has already resolved the connection's hostname
// to — so a hostname that resolves to a loopback or link-local address
// (DNS rebinding) is rejected at dial time even though CheckURL, given
// only the hostname, had nothing to reject (contract: "the URL policy runs
// at create/update and again at dial time").
func DialControl(allowLoopback bool) func(network, address string, c syscall.RawConn) error {
	return func(_, address string, _ syscall.RawConn) error {
		host, _, err := net.SplitHostPort(address)
		if err != nil {
			return fmt.Errorf("httpx: %w", err)
		}
		return CheckHost(host, allowLoopback)
	}
}
