// Package flow assembles the "system map": how an org's certificates connect
// to issuers, delivery, clients and alert channels. Assemble is pure; Builder
// (build.go) gathers its input from the existing stores.
package flow

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Status of a node or edge.
type Status string

// Statuses, mirroring the API's FlowStatus enum.
const (
	StatusValid    Status = "valid"
	StatusExpiring Status = "expiring"
	StatusExpired  Status = "expired"
	StatusFailed   Status = "failed"
	StatusDrift    Status = "drift"
	StatusPending  Status = "pending"
	StatusIdle     Status = "idle"
)

// Node kinds, mirroring the API's FlowNode kind enum.
const (
	KindCA            = "ca"
	KindAccount       = "account"
	KindDNSCredential = "dnsCredential"
	KindCertificate   = "certificate"
	KindLayout        = "layout"
	KindTarget        = "target"
	KindHook          = "hook"
	KindClient        = "client"
	KindChannel       = "channel"
)

const (
	// MaxNodes caps the whole map.
	MaxNodes = 500
	// maxSideNodes is the share of MaxNodes the non-certificate lanes may use
	// together; certificates fill the rest (at least MaxNodes-maxSideNodes).
	maxSideNodes = 250
	// MaxEdges caps edges; inferred alert edges are dropped first.
	MaxEdges = 5000
	// ExpiringDays matches the web UI's EXPIRING_DAYS.
	ExpiringDays = 14
)

var statusRank = map[Status]int{StatusIdle: 0, StatusValid: 1, StatusPending: 2, StatusExpiring: 3, StatusExpired: 4, StatusDrift: 5, StatusFailed: 6}

// Worse returns the more severe of a and b.
func Worse(a, b Status) Status {
	if statusRank[b] > statusRank[a] {
		return b
	}
	return a
}

// Node is one box on the map.
type Node struct {
	ID           string
	Kind         string
	Name         string
	Status       Status
	StatusDetail string
	Href         string
	// CoversCertificates is set on channel nodes that would receive this
	// org's certificate events.
	CoversCertificates bool
}

// Lane is one column.
type Lane struct {
	Hidden bool
	Nodes  []Node
}

// Edge connects two node ids.
type Edge struct {
	From, To string
	Status   Status
	// CertID scopes a delivery -> client edge to one certificate, so tracing
	// a certificate does not light up another one's clients. Empty when a
	// certificate is already an endpoint.
	CertID string
}

// Graph is the assembled map.
type Graph struct {
	Issuers, Certificates, Delivery, Clients, Alerts Lane
	Edges                                            []Edge
	Truncated                                        bool
	GeneratedAt                                      time.Time
}

// Perms says which lanes the caller may read. Certificates is implied (the
// handler refuses callers without it).
type Perms struct {
	CAs, Accounts, DNSCreds, Delivery, Clients, Alerts bool
}

// Item is a named resource. Detail picks a variant of its web path (a CA's
// type, say).
type Item struct {
	ID     uuid.UUID
	Name   string
	Detail string
	// NotAfter is a private CA's own certificate expiry; nil otherwise.
	NotAfter *time.Time
	// Health is an ACME account's registration status ("" when not applicable).
	Health string
}

// Cert is a certificate with what its edges need already resolved.
type Cert struct {
	ID         uuid.UUID
	Name       string
	Status     string // issuance.Status*
	LastError  string
	NotAfter   *time.Time
	CAID       *uuid.UUID
	AccountID  *uuid.UUID
	DNSCredIDs []uuid.UUID
}

// Client is an enrolled agent host.
type Client struct {
	ID     uuid.UUID
	Name   string
	Status string // pending, active, revoked
}

// Grant is one cert delivery. ClientID is nil for a server-run target.
// State is the deployment state: agent ok/pending/failed/drift, server
// deployed/pending/failed, or "" when no deployment row exists.
type Grant struct {
	CertID   uuid.UUID
	ClientID *uuid.UUID
	LayoutID *uuid.UUID
	TargetID *uuid.UUID
	HookIDs  []uuid.UUID
	State    string
	Error    string
}

// Channel is a notification channel of the org.
type Channel struct {
	ID          uuid.UUID
	Name        string
	Enabled     bool
	Events      []string // empty means every kind
	MinSeverity string
	LastStatus  string // delivered, failed, pending; "" when none yet
	LastError   string
	LastAt      *time.Time // when the last delivery was made or last changed
}

// Input is everything Assemble needs.
type Input struct {
	OrgSlug  string
	Certs    []Cert
	CAs      []Item // Detail is the CA type
	Accounts []Item
	DNSCreds []Item
	Layouts  []Item
	Targets  []Item
	Hooks    []Item
	Clients  []Client
	Grants   []Grant
	Channels []Channel
	// CertsMore is true when the certificate list itself was cut short.
	CertsMore bool
	// Uses is the issuer references of every certificate in the org, for
	// counting issuer use. Nil means Certs is the whole org.
	Uses []Use
}

// Use is the issuer entities one certificate resolves to.
type Use struct {
	CAID, AccountID *uuid.UUID
	DNSCredIDs      []uuid.UUID
}

// certEventKinds are the event kinds a certificate emits, with severities.
var certEventKinds = map[string]string{
	"cert.issued": "info", "cert.renewal_failed": "warning", "cert.expiring": "warning", "cert.expired": "critical",
}

var sevRank = map[string]int{"info": 0, "warning": 1, "critical": 2}

// ChannelCoversCerts reports whether an enabled channel would receive at
// least one certificate event: its kind list is empty or names a certificate
// kind whose severity reaches its minimum severity.
func ChannelCoversCerts(c Channel) bool {
	if !c.Enabled {
		return false
	}
	min := sevRank[c.MinSeverity]
	for kind, sev := range certEventKinds {
		if len(c.Events) > 0 && !slices.Contains(c.Events, kind) {
			continue
		}
		if sevRank[sev] >= min {
			return true
		}
	}
	return false
}

// CertStatus maps a certificate's stored status and expiry to a Status.
func CertStatus(c Cert, now time.Time) (Status, string) {
	switch c.Status {
	case "pending":
		return StatusPending, ""
	case "failed":
		return StatusFailed, c.LastError
	case "expired":
		return StatusExpired, ""
	case "revoked":
		return StatusFailed, "revoked"
	}
	if c.NotAfter == nil {
		return StatusValid, ""
	}
	left := c.NotAfter.Sub(now)
	switch {
	case left <= 0:
		return StatusExpired, ""
	case left < ExpiringDays*24*time.Hour:
		return StatusExpiring, fmt.Sprintf("expires in %d days", int(left.Hours()/24))
	}
	return StatusValid, ""
}

// GrantStatus maps a deployment state to an edge Status.
func GrantStatus(state string) Status {
	switch state {
	case "ok", "deployed":
		return StatusValid
	case "failed":
		return StatusFailed
	case "drift":
		return StatusDrift
	case "pending":
		return StatusPending
	}
	return StatusPending
}

// usage is the status of an issuer entity that has no health of its own.
func usage(n int) (Status, string) {
	switch n {
	case 0:
		return StatusIdle, "Not used by any certificate"
	case 1:
		return StatusValid, "Used by 1 certificate"
	}
	return StatusValid, fmt.Sprintf("Used by %d certificates", n)
}

func nid(kind string, id uuid.UUID) string { return kind + ":" + id.String() }

type builder struct {
	in    Input
	perms Perms
	now   time.Time
	base  string
	nodes map[string]*Node
	edges map[[3]string]*Edge
	order [][3]string
}

func (b *builder) edge(from, to, certID string, st Status) {
	k := [3]string{from, to, certID}
	if e, ok := b.edges[k]; ok {
		e.Status = Worse(e.Status, st)
		return
	}
	b.edges[k] = &Edge{From: from, To: to, Status: st, CertID: certID}
	b.order = append(b.order, k)
}

func (b *builder) href(parts ...string) string { return b.base + strings.Join(parts, "") }

// Assemble builds the graph. Lanes the caller may not read come back hidden
// and empty, and any edge touching a node that is absent (hidden lane, or cut
// by the cap) is dropped.
func Assemble(in Input, perms Perms, now time.Time) Graph {
	b := &builder{in: in, perms: perms, now: now, base: "/o/" + in.OrgSlug,
		nodes: map[string]*Node{}, edges: map[[3]string]*Edge{}}
	g := Graph{GeneratedAt: now}

	// Issuer usage: how many certificates resolve to each issuer entity.
	uses := in.Uses
	if uses == nil {
		for _, c := range in.Certs {
			uses = append(uses, Use{CAID: c.CAID, AccountID: c.AccountID, DNSCredIDs: c.DNSCredIDs})
		}
	}
	used := map[string]int{}
	for _, u := range uses {
		if u.CAID != nil {
			used[nid(KindCA, *u.CAID)]++
		}
		if u.AccountID != nil {
			used[nid(KindAccount, *u.AccountID)]++
		}
		for _, d := range u.DNSCredIDs {
			used[nid(KindDNSCredential, d)]++
		}
	}

	// Side lanes first so certificates get what is left of the cap.
	var issuers, delivery, clients, alerts []Node
	if perms.CAs {
		for _, c := range in.CAs {
			q := "?edit="
			if c.Detail == "localca" || c.Detail == "vaultpki" {
				q = "?view="
			}
			st, d := usage(used[nid(KindCA, c.ID)])
			if c.NotAfter != nil {
				if left := c.NotAfter.Sub(now); left <= 0 {
					st, d = StatusExpired, "CA certificate expired"
				} else if left < ExpiringDays*24*time.Hour {
					st, d = StatusExpiring, fmt.Sprintf("CA certificate expires in %d days", int(left.Hours()/24))
				}
			}
			issuers = append(issuers, Node{ID: nid(KindCA, c.ID), Kind: KindCA, Name: c.Name, Status: st, StatusDetail: d, Href: b.href("/issuers/cas", q, c.ID.String())})
		}
	}
	if perms.Accounts {
		for _, a := range in.Accounts {
			st, d := usage(used[nid(KindAccount, a.ID)])
			if a.Health != "" && a.Health != "valid" {
				st, d = StatusFailed, "Registration status: "+a.Health
			}
			issuers = append(issuers, Node{ID: nid(KindAccount, a.ID), Kind: KindAccount, Name: a.Name, Status: st, StatusDetail: d, Href: b.href("/issuers/accounts")})
		}
	}
	if perms.DNSCreds {
		for _, d := range in.DNSCreds {
			st, det := usage(used[nid(KindDNSCredential, d.ID)])
			issuers = append(issuers, Node{ID: nid(KindDNSCredential, d.ID), Kind: KindDNSCredential, Name: d.Name, Status: st, StatusDetail: det, Href: b.href("/issuers/dns")})
		}
	}
	if perms.Delivery {
		for _, l := range in.Layouts {
			delivery = append(delivery, Node{ID: nid(KindLayout, l.ID), Kind: KindLayout, Name: l.Name, Status: StatusIdle, Href: b.href("/delivery/layouts?edit=", l.ID.String())})
		}
		for _, t := range in.Targets {
			delivery = append(delivery, Node{ID: nid(KindTarget, t.ID), Kind: KindTarget, Name: t.Name, Status: StatusIdle, Href: b.href("/delivery/targets?edit=", t.ID.String())})
		}
		for _, h := range in.Hooks {
			delivery = append(delivery, Node{ID: nid(KindHook, h.ID), Kind: KindHook, Name: h.Name, Status: StatusIdle, Href: b.href("/delivery/hooks?edit=", h.ID.String())})
		}
	}
	if perms.Clients {
		for _, c := range in.Clients {
			st, d := StatusValid, ""
			switch c.Status {
			case "pending":
				st, d = StatusPending, "not enrolled yet"
			case "revoked":
				st, d = StatusFailed, "revoked"
			}
			clients = append(clients, Node{ID: nid(KindClient, c.ID), Kind: KindClient, Name: c.Name, Status: st, StatusDetail: d, Href: b.href("/clients/", c.ID.String())})
		}
	}
	if perms.Alerts {
		for _, c := range in.Channels {
			st, d := StatusIdle, ""
			switch {
			case !c.Enabled:
				d = "Disabled"
			case c.LastStatus == "delivered":
				st, d = StatusValid, "Last delivered"
				if c.LastAt != nil {
					d += " " + c.LastAt.UTC().Format("2006-01-02 15:04 UTC")
				}
			case c.LastStatus == "failed":
				st, d = StatusFailed, "Last delivery failed"
				if c.LastError != "" {
					d += ": " + c.LastError
				}
			case c.LastStatus == "":
				d = "No deliveries yet"
			default: // queued or retrying
				st, d = StatusPending, "Delivery pending"
			}
			alerts = append(alerts, Node{ID: nid(KindChannel, c.ID), Kind: KindChannel, Name: c.Name, Status: st, StatusDetail: d, Href: b.href("/alerts/channels?edit=", c.ID.String()), CoversCertificates: ChannelCoversCerts(c)})
		}
	}

	// Cap: side lanes share maxSideNodes in lane order; certificates the rest.
	side := [][]Node{issuers, delivery, clients, alerts}
	budget := maxSideNodes
	for i := range side {
		if len(side[i]) > budget {
			side[i] = side[i][:budget]
			g.Truncated = true
		}
		budget -= len(side[i])
	}
	issuers, delivery, clients, alerts = side[0], side[1], side[2], side[3]
	certBudget := MaxNodes - (maxSideNodes - budget)
	certs := in.Certs
	if len(certs) > certBudget {
		certs = certs[:certBudget]
		g.Truncated = true
	}
	if in.CertsMore {
		g.Truncated = true
	}

	var certNodes []Node
	for _, c := range certs {
		st, d := CertStatus(c, now)
		certNodes = append(certNodes, Node{ID: nid(KindCertificate, c.ID), Kind: KindCertificate, Name: c.Name, Status: st, StatusDetail: d, Href: b.href("/certificates/", c.ID.String())})
	}

	for _, ns := range [][]Node{issuers, certNodes, delivery, clients, alerts} {
		for i := range ns {
			n := ns[i]
			b.nodes[n.ID] = &n
		}
	}

	// Issuer edges: cert -> CA / account / DNS credential, coloured by the cert.
	for _, c := range certs {
		cid := nid(KindCertificate, c.ID)
		st := b.nodes[cid].Status
		if c.CAID != nil {
			b.edge(cid, nid(KindCA, *c.CAID), "", st)
		}
		if c.AccountID != nil {
			b.edge(cid, nid(KindAccount, *c.AccountID), "", st)
		}
		for _, d := range c.DNSCredIDs {
			b.edge(cid, nid(KindDNSCredential, d), "", st)
		}
	}

	// Delivery edges: cert -> layout/target/hook -> client.
	for _, gr := range in.Grants {
		cid := nid(KindCertificate, gr.CertID)
		st := GrantStatus(gr.State)
		var mids []string
		if gr.LayoutID != nil {
			mids = append(mids, nid(KindLayout, *gr.LayoutID))
		}
		if gr.TargetID != nil {
			mids = append(mids, nid(KindTarget, *gr.TargetID))
		}
		for _, h := range gr.HookIDs {
			mids = append(mids, nid(KindHook, h))
		}
		var client string
		if gr.ClientID != nil {
			client = nid(KindClient, *gr.ClientID)
		}
		// Middle nodes that are absent (hidden lane or cut by the cap) are
		// skipped; with none left, link the certificate straight to its client.
		present := mids[:0:0]
		for _, m := range mids {
			if b.nodes[m] != nil {
				present = append(present, m)
			}
		}
		if len(present) == 0 {
			if client != "" {
				b.edge(cid, client, "", st)
			}
			continue
		}
		for _, m := range present {
			b.edge(cid, m, "", st)
			if client != "" {
				b.edge(m, client, gr.CertID.String(), st)
			}
			n := b.nodes[m]
			n.Status = Worse(n.Status, st)
			if st == StatusFailed && n.StatusDetail == "" {
				n.StatusDetail = gr.Error
			}
		}
	}

	// Emit edges whose endpoints both exist, in insertion order.
	for _, k := range b.order {
		e := b.edges[k]
		if b.nodes[e.From] == nil || b.nodes[e.To] == nil {
			continue
		}
		if len(g.Edges) >= MaxEdges {
			g.Truncated = true
			break
		}
		g.Edges = append(g.Edges, *e)
	}

	// Lanes from the (possibly status-updated) nodes, keeping lane order.
	fill := func(ns []Node, hidden bool) Lane {
		l := Lane{Hidden: hidden, Nodes: []Node{}}
		for _, n := range ns {
			l.Nodes = append(l.Nodes, *b.nodes[n.ID])
		}
		return l
	}
	g.Issuers = fill(issuers, (!perms.CAs && !perms.Accounts && !perms.DNSCreds))
	g.Certificates = fill(certNodes, false)
	g.Delivery = fill(delivery, !perms.Delivery)
	g.Clients = fill(clients, !perms.Clients)
	g.Alerts = fill(alerts, !perms.Alerts)
	if g.Edges == nil {
		g.Edges = []Edge{}
	}
	return g
}
