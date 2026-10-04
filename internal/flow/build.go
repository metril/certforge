package flow

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/issuance"
)

// Builder gathers a map's input from the existing stores.
type Builder struct {
	// Pool, when set, makes Build read through one read-only REPEATABLE READ
	// transaction so the map's queries see a single snapshot.
	Pool     *pgxpool.Pool
	Q        *sqlcgen.Queries
	Issuance *issuance.Store
	Certs    *certstore.Store
	Now      func() time.Time // nil: time.Now
}

// Build assembles orgID's map. Only lanes perms allows are read from the
// database; certificates are always read.
func (b *Builder) Build(ctx context.Context, orgID uuid.UUID, perms Perms) (Graph, error) {
	if b.Pool == nil {
		return b.build(ctx, orgID, perms)
	}
	tx, err := b.Pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	if err != nil {
		return Graph{}, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	snap := *b
	snap.Q = b.Q.WithTx(tx)
	snap.Certs = b.Certs.WithTx(tx)
	// GlobalDefaults reads one settings row through the settings service,
	// outside this transaction; acceptable for a single row.
	snap.Issuance = b.Issuance.WithTx(tx)
	return snap.build(ctx, orgID, perms)
}

func (b *Builder) build(ctx context.Context, orgID uuid.UUID, perms Perms) (Graph, error) {
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
		in.CAs = append(in.CAs, Item{ID: c.ID, Name: c.Name, Detail: c.Type, NotAfter: caExpiry(c.Type, c.NotAfter)})
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
			in.Accounts = append(in.Accounts, Item{ID: a.ID, Name: a.Email, Health: a.Status})
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

// loadCerts reads the certificates the map shows (by name, up to the node
// cap) and, separately, the issuer references of every certificate in the
// org, so issuer use counts are exact whatever the org's size. Global and org
// defaults are read once, as the certificate list does.
func (b *Builder) loadCerts(ctx context.Context, orgID uuid.UUID, in *Input) error {
	pg, err := b.Issuance.ListCertificatesPage(ctx, []uuid.UUID{orgID}, issuance.ListQuery{Sort: issuance.SortName, Limit: MaxNodes})
	if err != nil {
		return err
	}
	certs := pg.Certificates
	in.CertsMore = pg.NextCursor != nil
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
	// resolve is one certificate's effective CA, account and DNS credentials.
	resolve := func(overrides issuance.Defaults, rules []challenge.RuleSpec) Use {
		eff := issuance.Resolve(global, org, overrides)
		if id := eff.CAID.Value; id != nil {
			eff = issuance.DropAccountForPrivateCA(eff, issuance.CA{Type: caType[*id]})
		}
		u := Use{CAID: eff.CAID.Value, AccountID: eff.AccountID.Value}
		seen := map[uuid.UUID]bool{}
		for _, r := range append(append([]challenge.RuleSpec{}, rules...), eff.VerificationRules.Value...) {
			if r.DNSCredentialID != nil && !seen[*r.DNSCredentialID] {
				seen[*r.DNSCredentialID] = true
				u.DNSCredIDs = append(u.DNSCredIDs, *r.DNSCredentialID)
			}
		}
		return u
	}
	for _, c := range certs {
		u := resolve(c.Overrides, c.Rules)
		fc := Cert{ID: c.ID, Name: c.Name, Status: c.Status, LastError: c.LastError, CAID: u.CAID, AccountID: u.AccountID, DNSCredIDs: u.DNSCredIDs}
		if c.CurrentVersionID != nil {
			if v, ok := versions[*c.CurrentVersionID]; ok {
				na := v.NotAfter
				fc.NotAfter = &na
			}
		}
		in.Certs = append(in.Certs, fc)
	}
	refs, err := b.Q.ListCertificateIssuerRefs(ctx, orgID)
	if err != nil {
		return err
	}
	in.Uses = make([]Use, 0, len(refs))
	for _, r := range refs {
		var rules []challenge.RuleSpec
		var overrides issuance.Defaults
		if err := json.Unmarshal(r.VerificationRules, &rules); err != nil {
			return err
		}
		if err := json.Unmarshal(r.Overrides, &overrides); err != nil {
			return err
		}
		in.Uses = append(in.Uses, resolve(overrides, rules))
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
			t := d.UpdatedAt
			if d.DeliveredAt != nil {
				t = *d.DeliveredAt
			}
			c.LastAt = &t
			if d.LastError != "" {
				c.LastError = d.LastError
			}
		}
		in.Channels = append(in.Channels, c)
	}
	return nil
}

// caExpiry is the expiry of a private CA's own certificate (ACME CAs have none).
func caExpiry(caType string, notAfter *time.Time) *time.Time {
	if caType == "acme" {
		return nil
	}
	return notAfter
}
