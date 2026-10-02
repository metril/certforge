package api

import (
	"context"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/flow"
)

// GetFlow returns the org's system map. certs:read is required; every other
// lane is returned hidden (no nodes, no edges touching it) when the caller
// lacks its own read permission.
func (s *Server) GetFlow(ctx context.Context, r gen.GetFlowRequestObject) (gen.GetFlowResponseObject, error) {
	p, err := authorize(ctx, authz.ActionCertsRead, &r.OrgId)
	if err != nil {
		return nil, err
	}
	can := func(a authz.Action) bool { return authz.Can(p, a, &r.OrgId) }
	perms := flow.Perms{
		CAs: can(authz.ActionCAsRead), Accounts: can(authz.ActionAccountsRead), DNSCreds: can(authz.ActionDNSCredsRead),
		Delivery: can(authz.ActionDeliveryRead), Clients: can(authz.ActionClientsRead), Alerts: can(authz.ActionAlertsRead),
	}
	b := flow.Builder{Q: s.queries(), Issuance: s.d.Issuance.Store, Certs: s.d.Certs}
	g, err := b.Build(ctx, r.OrgId, perms)
	if err != nil {
		return nil, err
	}
	return gen.GetFlow200JSONResponse(flowOut(g)), nil
}

func flowOut(g flow.Graph) gen.Flow {
	lane := func(l flow.Lane) gen.FlowLane {
		nodes := make([]gen.FlowNode, 0, len(l.Nodes))
		for _, n := range l.Nodes {
			fn := gen.FlowNode{Id: n.ID, Kind: gen.FlowNodeKind(n.Kind), Name: n.Name, Status: gen.FlowStatus(n.Status), Href: n.Href}
			if n.StatusDetail != "" {
				fn.StatusDetail = ptr(n.StatusDetail)
			}
			if n.CoversCertificates {
				fn.CoversCertificates = ptr(true)
			}
			nodes = append(nodes, fn)
		}
		return gen.FlowLane{Hidden: l.Hidden, Nodes: nodes}
	}
	edges := make([]gen.FlowEdge, 0, len(g.Edges))
	for _, e := range g.Edges {
		fe := gen.FlowEdge{From: e.From, To: e.To, Status: gen.FlowStatus(e.Status)}
		if e.CertID != "" {
			if id, err := uuid.Parse(e.CertID); err == nil {
				fe.CertificateId = &id
			}
		}
		edges = append(edges, fe)
	}
	return gen.Flow{
		Lanes: gen.FlowLanes{Issuers: lane(g.Issuers), Certificates: lane(g.Certificates), Delivery: lane(g.Delivery),
			Clients: lane(g.Clients), Alerts: lane(g.Alerts)},
		Edges: edges, Truncated: g.Truncated, GeneratedAt: g.GeneratedAt,
	}
}
