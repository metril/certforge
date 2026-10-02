package flow

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/issuance"
)

// Builder gathers a map's input from the existing stores.
type Builder struct {
	Q        *sqlcgen.Queries
	Issuance *issuance.Store
	Certs    *certstore.Store
	Now      func() time.Time // nil: time.Now
}

// Build assembles orgID's map. Only lanes perms allows are read from the
// database; certificates are always read.
func (b *Builder) Build(ctx context.Context, orgID uuid.UUID, perms Perms) (Graph, error) {
	now := time.Now()
	if b.Now != nil {
		now = b.Now()
	}
	org, err := b.Q.GetOrg(ctx, orgID)
	if err != nil {
		return Graph{}, err
	}
	in := Input{OrgSlug: org.Slug}

	// CA rows are read even when the CA lane is hidden: effective-account
	// resolution needs each CA's type. Assemble only emits them as nodes
	// when perms.CAs.
	cas, err := b.Q.ListCAs(ctx, orgID)
	if err != nil {
		return Graph{}, err
	}
	for _, c := range cas {
		in.CAs = append(in.CAs, Item{ID: c.ID, Name: c.Name, Detail: c.Type})
	}
	if err := b.loadCerts(ctx, orgID, &in); err != nil {
		return Graph{}, err
	}
	if perms.Accounts {
		rows, err := b.Q.ListAccounts(ctx, orgID)
		if err != nil {
			return Graph{}, err
		}
		for _, a := range rows {
			in.Accounts = append(in.Accounts, Item{ID: a.ID, Name: a.Email})
		}
	}
	if perms.DNSCreds {
		rows, err := b.Q.ListDNSCredentials(ctx, orgID)
		if err != nil {
			return Graph{}, err
		}
		for _, d := range rows {
			in.DNSCreds = append(in.DNSCreds, Item{ID: d.ID, Name: d.Name})
		}
	}
	if perms.Delivery {
		if err := b.loadDelivery(ctx, orgID, &in); err != nil {
			return Graph{}, err
		}
	}
	if perms.Clients {
		rows, err := b.Q.ListClients(ctx, sqlcgen.ListClientsParams{OrgIds: []uuid.UUID{orgID}, Sort: "name", PageLimit: MaxNodes})
		if err != nil {
			return Graph{}, err
		}
		for _, c := range rows {
			in.Clients = append(in.Clients, Client{ID: c.ID, Name: c.Name, Status: c.Status})
		}
	}
	if perms.Delivery || perms.Clients {
		if err := b.loadGrants(ctx, orgID, &in); err != nil {
			return Graph{}, err
		}
	}
	if perms.Alerts {
		if err := b.loadChannels(ctx, orgID, &in); err != nil {
			return Graph{}, err
		}
	}
	return Assemble(in, perms, now), nil
}

// loadCerts reads the org's certificates (first MaxNodes+1 by name) and
// resolves each one's effective CA, account and DNS credentials. Global and
// org defaults are read once, as the certificate list does.
func (b *Builder) loadCerts(ctx context.Context, orgID uuid.UUID, in *Input) error {
	pg, err := b.Issuance.ListCertificatesPage(ctx, []uuid.UUID{orgID}, issuance.ListQuery{Sort: issuance.SortName, Limit: MaxNodes + 1})
	if err != nil {
		return err
	}
	certs := pg.Certificates
	if len(certs) > MaxNodes {
		certs = certs[:MaxNodes]
		in.CertsMore = true
	}
	if pg.NextCursor != nil {
		in.CertsMore = true
	}
	global, err := b.Issuance.GlobalDefaults(ctx)
	if err != nil {
		return err
	}
	org, err := b.Issuance.OrgDefaults(ctx, orgID)
	if err != nil {
		return err
	}
	var vids []uuid.UUID
	for _, c := range certs {
		if c.CurrentVersionID != nil {
			vids = append(vids, *c.CurrentVersionID)
		}
	}
	versions, err := b.Certs.Versions(ctx, vids)
	if err != nil {
		return err
	}
	caType := map[uuid.UUID]string{}
	for _, c := range in.CAs {
		caType[c.ID] = c.Detail
	}
	for _, c := range certs {
		eff := issuance.Resolve(global, org, c.Overrides)
		if id := eff.CAID.Value; id != nil {
			eff = issuance.DropAccountForPrivateCA(eff, issuance.CA{Type: caType[*id]})
		}
		fc := Cert{ID: c.ID, Name: c.Name, Status: c.Status, LastError: c.LastError, CAID: eff.CAID.Value, AccountID: eff.AccountID.Value}
		if c.CurrentVersionID != nil {
			if v, ok := versions[*c.CurrentVersionID]; ok {
				na := v.NotAfter
				fc.NotAfter = &na
			}
		}
		seen := map[uuid.UUID]bool{}
		for _, r := range append(append([]challenge.RuleSpec{}, c.Rules...), eff.VerificationRules.Value...) {
			if r.DNSCredentialID != nil && !seen[*r.DNSCredentialID] {
				seen[*r.DNSCredentialID] = true
				fc.DNSCredIDs = append(fc.DNSCredIDs, *r.DNSCredentialID)
			}
		}
		in.Certs = append(in.Certs, fc)
	}
	return nil
}

func (b *Builder) loadDelivery(ctx context.Context, orgID uuid.UUID, in *Input) error {
	ls, err := b.Q.ListLayouts(ctx, orgID)
	if err != nil {
		return err
	}
	for _, l := range ls {
		in.Layouts = append(in.Layouts, Item{ID: l.ID, Name: l.Name})
	}
	ts, err := b.Q.ListDeployTargets(ctx, orgID)
	if err != nil {
		return err
	}
	for _, t := range ts {
		in.Targets = append(in.Targets, Item{ID: t.ID, Name: t.Name, Detail: t.RunsOn})
	}
	hs, err := b.Q.ListHooks(ctx, orgID)
	if err != nil {
		return err
	}
	for _, h := range hs {
		in.Hooks = append(in.Hooks, Item{ID: h.ID, Name: h.Name})
	}
	return nil
}

// loadGrants reads the org's live agent grants (with deployment state) and
// server grants (client-less, with server deployment state).
func (b *Builder) loadGrants(ctx context.Context, orgID uuid.UUID, in *Input) error {
	rows, err := b.Q.GrantViews(ctx, sqlcgen.GrantViewsParams{OrgID: orgID})
	if err != nil {
		return err
	}
	for _, g := range rows {
		in.Grants = append(in.Grants, Grant{CertID: g.CertID, ClientID: g.ClientID, LayoutID: g.OutputSpecID,
			TargetID: g.DeployTargetID, HookIDs: g.HookIds, State: g.State, Error: g.Error})
	}
	srows, err := b.Q.ServerGrantViews(ctx, sqlcgen.ServerGrantViewsParams{OrgID: orgID})
	if err != nil {
		return err
	}
	for _, g := range srows {
		gr := Grant{CertID: g.CertID, LayoutID: g.OutputSpecID, TargetID: g.DeployTargetID, HookIDs: g.HookIds}
		if g.Status != nil {
			gr.State = *g.Status
		}
		if g.LastError != nil {
			gr.Error = *g.LastError
		}
		in.Grants = append(in.Grants, gr)
	}
	return nil
}

func (b *Builder) loadChannels(ctx context.Context, orgID uuid.UUID, in *Input) error {
	rows, err := b.Q.ListOrgNotificationChannels(ctx, sqlcgen.ListOrgNotificationChannelsParams{OrgID: orgID})
	if err != nil {
		return err
	}
	ids := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	last := map[uuid.UUID]sqlcgen.ChannelsLastDeliveryRow{}
	if len(ids) > 0 {
		ld, err := b.Q.ChannelsLastDelivery(ctx, ids)
		if err != nil {
			return err
		}
		for _, d := range ld {
			last[d.ChannelID] = d
		}
	}
	for _, r := range rows {
		c := Channel{ID: r.ID, Name: r.Name, Enabled: r.Enabled, Events: r.Events, MinSeverity: r.MinSeverity}
		if d, ok := last[r.ID]; ok {
			c.LastStatus = d.Status
			if d.LastError != "" {
				c.LastError = d.LastError
			}
		}
		in.Channels = append(in.Channels, c)
	}
	return nil
}
