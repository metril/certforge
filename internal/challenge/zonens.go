package challenge

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"
)

// lego's dns01 zone lookup (FindZoneByFqdn, used by providers and by the
// CNAME follow in GetChallengeInfo) reads a package-global nameserver list,
// so it cannot be set per issuance. Instead the server starts one loopback
// forwarder at boot and points lego at it once; each Router registers the
// names it validates with the resolvers that apply to them, and the
// forwarder answers each query from the matching registration.

// defaultResolvers supplies the global Issuance resolvers, used when no
// registration (or several different ones) matches a query; nil or empty
// falls back to /etc/resolv.conf.
var defaultResolvers atomic.Pointer[func() []string]

// SetDefaultResolvers installs the hook returning the global Issuance
// resolvers (nil clears it). It returns the previous hook.
func SetDefaultResolvers(f func() []string) (prev func() []string) {
	var old *func() []string
	if f == nil {
		old = defaultResolvers.Swap(nil)
	} else {
		old = defaultResolvers.Swap(&f)
	}
	if old == nil {
		return nil
	}
	return *old
}

var (
	zoneAddr atomic.Pointer[string]

	zoneMu   sync.Mutex
	zoneRegs = map[*zoneReg]struct{}{}
)

type zoneReg struct {
	names     []string // normalized, no wildcard
	resolvers []string
	key       string
}

// ZoneForwarderAddr returns the forwarder's host:port, or "" when it has not
// been started.
func ZoneForwarderAddr() string {
	if p := zoneAddr.Load(); p != nil {
		return *p
	}
	return ""
}

func zoneName(n string) string {
	n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
	return strings.TrimPrefix(n, "*.")
}

// RegisterZone routes zone-lookup queries for names (and their parents, and the
// _acme-challenge names under them) to resolvers until release is called.
// It clears lego's SOA cache so a zone found through other resolvers is not
// reused.
func RegisterZone(names, resolvers []string) (release func()) {
	reg := &zoneReg{resolvers: append([]string(nil), resolvers...), key: strings.Join(resolvers, "\x00")}
	for _, n := range names {
		if n = zoneName(n); n != "" {
			reg.names = append(reg.names, n)
		}
	}
	zoneMu.Lock()
	zoneRegs[reg] = struct{}{}
	zoneMu.Unlock()
	dns01.ClearFqdnCache()
	var once sync.Once
	return func() {
		once.Do(func() {
			zoneMu.Lock()
			delete(zoneRegs, reg)
			zoneMu.Unlock()
		})
	}
}

// resolversFor returns the one resolver list registered for qname, or nil
// when none or several different lists match.
func resolversFor(qname string) []string {
	q := strings.TrimPrefix(zoneName(qname), "_acme-challenge.")
	zoneMu.Lock()
	defer zoneMu.Unlock()
	var found *zoneReg
	for reg := range zoneRegs {
		for _, n := range reg.names {
			if q == "" || q == n || strings.HasSuffix(n, "."+q) {
				if found != nil && found.key != reg.key {
					return nil
				}
				found = reg
				break
			}
		}
	}
	if found == nil {
		return nil
	}
	return found.resolvers
}

func fallbackResolvers() []string {
	if f := defaultResolvers.Load(); f != nil {
		if r := (*f)(); len(r) > 0 {
			return r
		}
	}
	r, _ := systemNameservers()
	return r
}

func systemNameservers() ([]string, error) {
	cfg, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return nil, fmt.Errorf("read /etc/resolv.conf: %w", err)
	}
	var out []string
	for _, s := range cfg.Servers {
		out = append(out, net.JoinHostPort(s, cfg.Port))
	}
	return out, nil
}

// nameserverList is the plain nameserver list CheckTXTAuthoritative uses to
// find a zone's NS records: the forwarder when running, else /etc/resolv.conf.
func nameserverList() ([]string, error) {
	if a := ZoneForwarderAddr(); a != "" {
		return []string{a}, nil
	}
	return systemNameservers()
}

// StartZoneForwarder runs the forwarder on 127.0.0.1 (UDP and TCP, one
// ephemeral port) until ctx is done and returns its address. The caller
// points lego at it with dns01.AddRecursiveNameservers, once.
func StartZoneForwarder(ctx context.Context) (string, error) {
	h := dns.HandlerFunc(serveZoneQuery)
	var pc net.PacketConn
	var ln net.Listener
	for i := 0; ; i++ {
		var err error
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			return "", err
		}
		if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			break
		}
		_ = pc.Close()
		if i >= 20 {
			return "", err
		}
	}
	servers := []*dns.Server{{PacketConn: pc, Handler: h}, {Listener: ln, Handler: h}}
	for _, s := range servers {
		started := make(chan struct{})
		s.NotifyStartedFunc = func() { close(started) }
		go func() { _ = s.ActivateAndServe() }()
		<-started
	}
	go func() {
		<-ctx.Done()
		for _, s := range servers {
			_ = s.Shutdown()
		}
	}()
	addr := pc.LocalAddr().String()
	zoneAddr.Store(&addr)
	return addr, nil
}

func serveZoneQuery(w dns.ResponseWriter, r *dns.Msg) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var resp *dns.Msg
	if len(r.Question) == 1 {
		resolvers := resolversFor(r.Question[0].Name)
		if resolvers == nil {
			resolvers = fallbackResolvers()
		}
		resp = forward(ctx, resolvers, r)
	}
	if resp == nil {
		resp = new(dns.Msg)
		resp.SetRcode(r, dns.RcodeServerFailure)
	}
	resp.Id = r.Id
	if _, isUDP := w.RemoteAddr().(*net.UDPAddr); isUDP {
		size := 512
		if opt := r.IsEdns0(); opt != nil {
			size = int(opt.UDPSize())
		}
		resp.Truncate(size)
	}
	_ = w.WriteMsg(resp)
}

// forward asks each resolver in turn, returning the first answer (whatever
// its rcode), or nil when every transport failed.
func forward(ctx context.Context, resolvers []string, r *dns.Msg) *dns.Msg {
	for _, res := range resolvers {
		if in, _, err := exchange(ctx, res, r); err == nil && in != nil {
			return in
		}
	}
	return nil
}
