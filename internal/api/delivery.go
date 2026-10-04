package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/deploy"
	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/targets"
)

// maxLayoutPasswordLen is the contract's LayoutInput.password maxLength;
// enforced here too, not only by the OpenAPI request-validation middleware,
// since a caller of the strict-server methods directly (as every handler
// test in this package does) never goes through that middleware.
const maxLayoutPasswordLen = 128

// checkLayoutPassword validates a freshly provided (never "__unchanged__")
// layout password: the contract's max length, and, when needsJKS, the exact
// rule render.CheckJKSPassword itself enforces (ASCII, at least 6 Unicode
// characters) — not a looser check that would let a password through
// storage only to fail every later render (CreateGrant, Resync, OnVersion,
// the sweep).
func checkLayoutPassword(plain string, needsJKS bool) error {
	if len(plain) > maxLayoutPasswordLen {
		return unprocessable("password", "must be at most 128 characters")
	}
	if needsJKS {
		if err := render.CheckJKSPassword(plain); err != nil {
			return unprocessable("password", "must be ASCII and at least 6 characters when any file is jks")
		}
	}
	return nil
}

// mapDeliveryErr turns a delivery.FieldError into a 422.
func mapDeliveryErr(err error) error {
	var fe *delivery.FieldError
	if errors.As(err, &fe) {
		return unprocessable(fe.Field, fe.Msg)
	}
	return err
}

type dependent struct {
	client, cert string
	removing     bool
}

func dependentsConflict(kind string, deps []dependent) error {
	var parts []string
	for i, d := range deps {
		if i == 5 {
			parts = append(parts, "and more")
			break
		}
		p := d.client + "/" + d.cert
		if d.removing {
			p += " (removal pending)"
		}
		parts = append(parts, p)
	}
	return conflict("This %s is used by grants: %s. Change or delete those grants first.", kind, strings.Join(parts, ", "))
}

// extraCertConflict is DeleteCertificate's 409 when layoutNames (up to six,
// from LayoutsListingExtraCert) still bundle this certificate as an extra.
func extraCertConflict(layoutNames []string) error {
	var parts []string
	for i, name := range layoutNames {
		if i == 5 {
			parts = append(parts, "and more")
			break
		}
		parts = append(parts, name)
	}
	return conflict("This certificate is listed as an extra certificate by layouts: %s. Remove it from those layouts first.", strings.Join(parts, ", "))
}

// monitorConflict is DeleteCertificate's 409 when monitors (up to six, from
// MonitorsExpectingCert) still expect this certificate.
func monitorConflict(mons []sqlcgen.MonitorsExpectingCertRow) error {
	var parts []string
	for i, m := range mons {
		if i == 5 {
			parts = append(parts, "and more")
			break
		}
		parts = append(parts, fmt.Sprintf("%s (%s)", m.Name, m.ID))
	}
	return conflict("This certificate is expected by monitors: %s. Change or delete those monitors first.", strings.Join(parts, ", "))
}

func countMap[T any](rows []T, key func(T) (uuid.UUID, int64)) map[uuid.UUID]int {
	m := make(map[uuid.UUID]int, len(rows))
	for _, r := range rows {
		k, n := key(r)
		m[k] = int(n)
	}
	return m
}

// ---- layouts ----

func layoutFilesIn(in []gen.OutputFile) []delivery.OutputFile {
	out := make([]delivery.OutputFile, 0, len(in))
	for _, f := range in {
		parts := make([]string, 0, len(f.Parts))
		for _, p := range f.Parts {
			parts = append(parts, string(p))
		}
		of := delivery.OutputFile{Path: f.Path, Format: string(f.Format), Parts: parts, Owner: f.Owner, Group: f.Group, Mode: f.Mode}
		if f.Encoding != nil {
			of.Encoding = string(*f.Encoding)
		}
		if f.Alias != nil {
			of.Alias = *f.Alias
		}
		out = append(out, of)
	}
	return out
}

func layoutOut(l sqlcgen.OutputSpec, grants int) (gen.Layout, error) {
	var files []delivery.OutputFile
	if err := json.Unmarshal(l.Files, &files); err != nil {
		return gen.Layout{}, err
	}
	out := make([]gen.OutputFile, 0, len(files))
	for _, f := range files {
		parts := make([]gen.OutputPart, 0, len(f.Parts))
		for _, p := range f.Parts {
			parts = append(parts, gen.OutputPart(p))
		}
		of := gen.OutputFile{Path: f.Path, Format: gen.OutputFormat(f.Format), Parts: parts, Owner: f.Owner, Group: f.Group, Mode: f.Mode}
		if f.Encoding != "" {
			enc := gen.P12Encoding(f.Encoding)
			of.Encoding = &enc
		}
		if f.Alias != "" {
			alias := f.Alias
			of.Alias = &alias
		}
		out = append(out, of)
	}
	extraIDs := l.ExtraCertIds
	if extraIDs == nil {
		extraIDs = []uuid.UUID{}
	}
	return gen.Layout{Id: l.ID, OrgId: l.OrgID, Name: l.Name, Files: out, GrantCount: grants,
		PasswordSet: len(l.Password) > 0, ExtraCertificateIds: extraIDs, CreatedAt: l.CreatedAt, UpdatedAt: l.UpdatedAt}, nil
}

func (s *Server) layoutsOut(ctx context.Context, rows []sqlcgen.OutputSpec) ([]gen.Layout, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	counts, err := s.queries().LayoutGrantCounts(ctx, ids)
	if err != nil {
		return nil, err
	}
	cm := countMap(counts, func(r sqlcgen.LayoutGrantCountsRow) (uuid.UUID, int64) { return r.ID, r.Grants })
	out := make([]gen.Layout, 0, len(rows))
	for _, r := range rows {
		l, err := layoutOut(r, cm[r.ID])
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

func (s *Server) layoutOne(ctx context.Context, l sqlcgen.OutputSpec) (gen.Layout, error) {
	out, err := s.layoutsOut(ctx, []sqlcgen.OutputSpec{l})
	if err != nil {
		return gen.Layout{}, err
	}
	return out[0], nil
}

// layoutParsed is a LayoutInput's shape-validated fields, before the
// password (needs Box, which may fail) and extraCertificateIds (needs a
// DB round trip) are resolved.
type layoutParsed struct {
	name         string
	files        []delivery.OutputFile
	filesJSON    []byte
	password     *string // nil: omitted; "": clear; challenge.Unchanged: keep stored
	extraCertIDs []uuid.UUID
}

func parseLayoutInput(in *gen.LayoutInput) (layoutParsed, error) {
	if in == nil {
		return layoutParsed{}, badRequest("missing body")
	}
	name, err := cleanName("name", in.Name)
	if err != nil {
		return layoutParsed{}, err
	}
	files := layoutFilesIn(in.Files)
	if err := delivery.ValidateFiles(files); err != nil {
		return layoutParsed{}, mapDeliveryErr(err)
	}
	for i := range files {
		if len(files[i].Mode) == 3 {
			files[i].Mode = "0" + files[i].Mode
		}
	}
	filesJSON, err := json.Marshal(files)
	if err != nil {
		return layoutParsed{}, err
	}
	extraIDs := []uuid.UUID{}
	if in.ExtraCertificateIds != nil {
		extraIDs = *in.ExtraCertificateIds
	}
	if len(extraIDs) > 10 {
		return layoutParsed{}, unprocessable("extraCertificateIds", "at most 10 extra certificates")
	}
	seen := make(map[uuid.UUID]bool, len(extraIDs))
	for _, id := range extraIDs {
		if seen[id] {
			return layoutParsed{}, unprocessable("extraCertificateIds", "each certificate may appear once")
		}
		seen[id] = true
	}
	return layoutParsed{name: name, files: files, filesJSON: filesJSON, password: in.Password, extraCertIDs: extraIDs}, nil
}

// layoutFormats reports whether any of files needs an export password
// (p12 or jks) and whether any needs the stronger jks minimum length.
func layoutFormats(files []delivery.OutputFile) (needsPassword, needsJKS bool) {
	for _, f := range files {
		if f.Format == "p12" || f.Format == "jks" {
			needsPassword = true
		}
		if f.Format == "jks" {
			needsJKS = true
		}
	}
	return needsPassword, needsJKS
}

// checkLayoutExtraCerts locks (FOR KEY SHARE) and validates a layout's
// candidate extra certificates: each must be a certificate of orgID with a
// current version. Called inside the layout write's own transaction, so a
// concurrent certificate delete (which locks the row FOR UPDATE) serializes
// against it instead of racing a dangling reference into extra_cert_ids.
func (s *Server) checkLayoutExtraCerts(ctx context.Context, q *sqlcgen.Queries, orgID uuid.UUID, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	rows, err := q.LockCertsForExtra(ctx, sqlcgen.LockCertsForExtraParams{Ids: ids, OrgID: orgID})
	if err != nil {
		return err
	}
	if len(rows) != len(ids) {
		return unprocessable("extraCertificateIds", "each must be a certificate in this org")
	}
	for _, row := range rows {
		if row.CurrentVersionID == nil {
			return unprocessable("extraCertificateIds", "each must have a current version")
		}
	}
	return nil
}

// ListLayouts returns an org's output layouts.
func (s *Server) ListLayouts(ctx context.Context, r gen.ListLayoutsRequestObject) (gen.ListLayoutsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryRead, &r.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.queries().ListLayouts(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	items, err := s.layoutsOut(ctx, rows)
	if err != nil {
		return nil, err
	}
	return gen.ListLayouts200JSONResponse(gen.LayoutList{Items: items}), nil
}

// GetLayout returns one layout.
func (s *Server) GetLayout(ctx context.Context, r gen.GetLayoutRequestObject) (gen.GetLayoutResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryRead, &r.OrgId); err != nil {
		return nil, err
	}
	l, err := s.queries().GetLayout(ctx, sqlcgen.GetLayoutParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("layout %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	out, err := s.layoutOne(ctx, l)
	if err != nil {
		return nil, err
	}
	return gen.GetLayout200JSONResponse(out), nil
}

// layoutAuditDetails is a layout row's create/update audit shape: the
// files, whether a password is stored, and its extra certificates, never
// the password itself.
func layoutAuditDetails(name string, files []byte, password []byte, extraCertIDs []uuid.UUID) map[string]any {
	return map[string]any{"name": name, "files": json.RawMessage(files), "passwordSet": len(password) > 0, "extraCertificateIds": extraCertIDs}
}

// CreateLayout adds a layout.
func (s *Server) CreateLayout(ctx context.Context, r gen.CreateLayoutRequestObject) (gen.CreateLayoutResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	li, err := parseLayoutInput(r.Body)
	if err != nil {
		return nil, err
	}
	needsPassword, needsJKS := layoutFormats(li.files)
	var plain string
	switch {
	case li.password != nil && *li.password == challenge.Unchanged:
		return nil, unprocessable("password", "no stored password to keep on create; provide one")
	case li.password != nil:
		plain = *li.password
	}
	if needsPassword && plain == "" {
		return nil, unprocessable("password", "required when any file is p12 or jks")
	}
	if plain != "" {
		if err := checkLayoutPassword(plain, needsJKS); err != nil {
			return nil, err
		}
	}
	var sealed []byte
	if plain != "" {
		if sealed, err = s.d.Box.Seal(ctx, []byte(plain)); err != nil {
			return nil, err
		}
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	if err := s.checkLayoutExtraCerts(ctx, q, r.OrgId, li.extraCertIDs); err != nil {
		return nil, err
	}
	l, err := q.CreateLayout(ctx, sqlcgen.CreateLayoutParams{OrgID: r.OrgId, Name: li.name, Files: li.filesJSON,
		Password: sealed, ExtraCertIds: li.extraCertIDs})
	switch pgCode(err) {
	case pgUniqueViolation:
		return nil, conflict("A layout named %q exists in this org.", li.name)
	case pgForeignKeyViolation:
		return nil, notFound("org %s", r.OrgId)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "layout.create", ResourceType: "layout", ResourceID: l.ID.String(), OrgID: &l.OrgID,
		Details: layoutAuditDetails(l.Name, l.Files, l.Password, l.ExtraCertIds)})
	out, err := s.layoutOne(ctx, l)
	if err != nil {
		return nil, err
	}
	return gen.CreateLayout201JSONResponse(out), nil
}

// UpdateLayout replaces a layout.
func (s *Server) UpdateLayout(ctx context.Context, r gen.UpdateLayoutRequestObject) (gen.UpdateLayoutResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	li, err := parseLayoutInput(r.Body)
	if err != nil {
		return nil, err
	}
	needsPassword, needsJKS := layoutFormats(li.files)
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	// Final review finding 1: FOR UPDATE (LockLayout, not plain GetLayout)
	// — the kept password below is read and written back unchanged, so a
	// concurrent rewrap's CAS on this row's password column must not be
	// able to land between this read and UpdateLayout's own write.
	cur, err := q.LockLayout(ctx, sqlcgen.LockLayoutParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("layout %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	var sealed []byte
	switch {
	case li.password != nil && *li.password == challenge.Unchanged:
		if len(cur.Password) == 0 {
			return nil, unprocessable("password", "no stored password to keep; provide one")
		}
		sealed = cur.Password
		// The file list can change in the same update (a file could become
		// jks here for the first time), so the stored password — valid
		// under whatever rule applied when it was last written — must be
		// re-checked against jks's rule now, not assumed to still satisfy it.
		if needsJKS {
			plainBytes, err := s.d.Box.Open(ctx, sealed)
			if err != nil {
				return nil, err
			}
			if err := render.CheckJKSPassword(string(plainBytes)); err != nil {
				return nil, unprocessable("password", "the stored password does not satisfy jks's rule (ASCII, at least 6 characters); provide a new one")
			}
		}
	case li.password != nil && *li.password != "":
		if err := checkLayoutPassword(*li.password, needsJKS); err != nil {
			return nil, err
		}
		if sealed, err = s.d.Box.Seal(ctx, []byte(*li.password)); err != nil {
			return nil, err
		}
	default:
		// li.password is nil (omitted) or "" (explicit clear).
		sealed = nil
	}
	if needsPassword && len(sealed) == 0 {
		return nil, unprocessable("password", "required when any file is p12 or jks")
	}
	if err := s.checkLayoutExtraCerts(ctx, q, r.OrgId, li.extraCertIDs); err != nil {
		return nil, err
	}
	// batch-5 review: a server grant's layout may only ever render PEM
	// files (Task 11's own create/update-time rule, internal/api/grants.go
	// serverLayoutFiles) — but that check only ever ran against a *new*
	// grant, not an *existing* layout a server grant already depends on.
	// Without this, UpdateLayout could turn a layout backing a live server
	// grant into p12/jks/der, bypassing the rule entirely (agents.Resync
	// below never sees a server grant: LiveGrantIDsUsingLayout filters
	// client_id IS NOT NULL).
	serverGrants, err := q.ServerGrantsUsingLayout(ctx, r.Id)
	if err != nil {
		return nil, err
	}
	if len(serverGrants) > 0 {
		for _, f := range li.files {
			if f.Format != "pem" {
				return nil, unprocessable("files", "this layout is used by a server grant, which may only render pem files")
			}
		}
	}
	// 4A final review finding 1: a layout already granted to a certificate
	// works fine cert-only against a keyless current version (R10), but an
	// update that makes it need a key must be refused here — under the
	// locks already taken in this transaction — rather than stored and
	// left for the next Resync render to fail opaquely with
	// render.ErrNoKey (mapAgentErr's 500).
	if delivery.NeedsKey(li.files) {
		// A key-bearing layout under a live grant (agent or server) hands the
		// key to that grant's target, so it needs keys:export, same as the
		// grant paths. Checked under LockLayout, which grant creation's
		// FOR SHARE lock on the layout conflicts with.
		agentGrants, err := q.LiveGrantIDsUsingLayout(ctx, &r.Id)
		if err != nil {
			return nil, err
		}
		if len(agentGrants) > 0 || len(serverGrants) > 0 {
			if _, err := authorize(ctx, authz.ActionKeysExport, &r.OrgId); err != nil {
				return nil, err
			}
		}
		name, err := q.LayoutKeylessGrantCertificate(ctx, &r.Id)
		if err == nil {
			return nil, unprocessable("files", fmt.Sprintf("certificate %q has no stored private key; this layout would need one", name))
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	l, err := q.UpdateLayout(ctx, sqlcgen.UpdateLayoutParams{Name: li.name, Files: li.filesJSON, Password: sealed,
		ExtraCertIds: li.extraCertIDs, ID: r.Id, OrgID: r.OrgId})
	if pgCode(err) == pgUniqueViolation {
		return nil, conflict("A layout named %q exists in this org.", li.name)
	}
	if err != nil {
		return nil, err
	}
	// Server grants using this layout never go through agents.Resync
	// (above), so they get their own redeploy: mark pending and enqueue
	// certforge_server_deploy directly, in the same transaction as the
	// layout write.
	for _, sg := range serverGrants {
		if err := s.d.Dispatcher.EnqueueTx(ctx, tx, q, sg.ID, sg.CurrentVersionID); err != nil {
			return nil, err
		}
	}
	nudge, err := s.d.Agents.Resync(ctx, q, agents.RefLayout, l.ID)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	nudge()
	s.audit(ctx, audit.Event{Action: "layout.update", ResourceType: "layout", ResourceID: l.ID.String(), OrgID: &l.OrgID,
		Details: map[string]any{"before": layoutAuditDetails(cur.Name, cur.Files, cur.Password, cur.ExtraCertIds),
			"after": layoutAuditDetails(l.Name, l.Files, l.Password, l.ExtraCertIds)}})
	out, err := s.layoutOne(ctx, l)
	if err != nil {
		return nil, err
	}
	return gen.UpdateLayout200JSONResponse(out), nil
}

// DeleteLayout removes a layout no grant uses.
func (s *Server) DeleteLayout(ctx context.Context, r gen.DeleteLayoutRequestObject) (gen.DeleteLayoutResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	q := s.queries()
	cur, err := q.GetLayout(ctx, sqlcgen.GetLayoutParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("layout %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	deps, err := q.LayoutDependents(ctx, sqlcgen.LayoutDependentsParams{ID: &r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	if len(deps) > 0 {
		d := make([]dependent, len(deps))
		for i, x := range deps {
			d[i] = dependent{x.ClientName, x.CertificateName, x.Removing}
		}
		return nil, dependentsConflict("layout", d)
	}
	n, err := q.DeleteLayout(ctx, sqlcgen.DeleteLayoutParams{ID: r.Id, OrgID: r.OrgId})
	if pgCode(err) == pgForeignKeyViolation {
		return nil, conflict("This layout was just granted; try again.")
	}
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, notFound("layout %s", r.Id)
	}
	s.audit(ctx, audit.Event{Action: "layout.delete", ResourceType: "layout", ResourceID: r.Id.String(), OrgID: &r.OrgId,
		Details: map[string]any{"name": cur.Name}})
	return gen.DeleteLayout204Response{}, nil
}

// ---- deploy targets ----

// targetSecrets opens t.SecretCfg (nil/empty for a target with no stored
// secrets, or old itself nil on create) into its decrypted secret map,
// mirroring notify's resolveChannelSecrets / issuance's credFromRow — the
// established pattern for a *_cfg column of this shape.
func (s *Server) targetSecrets(ctx context.Context, old *sqlcgen.DeployTarget) (map[string]string, error) {
	if old == nil || len(old.SecretCfg) == 0 {
		return map[string]string{}, nil
	}
	pt, err := s.d.Box.Open(ctx, old.SecretCfg)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// storedSecretKeys returns m's keys, sorted — DeployTarget.storedSecrets.
func storedSecretKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Server) targetOut(ctx context.Context, t sqlcgen.DeployTarget, grants int) (gen.DeployTarget, error) {
	cfg := map[string]interface{}{}
	if err := json.Unmarshal(t.Config, &cfg); err != nil {
		return gen.DeployTarget{}, err
	}
	names := t.StoredSecretKeys
	if len(names) == 0 && len(t.SecretCfg) > 0 {
		// A row from before stored_secret_keys existed: open it once.
		secrets, err := s.targetSecrets(ctx, &t)
		if err != nil {
			return gen.DeployTarget{}, err
		}
		names = storedSecretKeys(secrets)
	}
	if names == nil {
		names = []string{}
	}
	return gen.DeployTarget{Id: t.ID, OrgId: t.OrgID, Name: t.Name, Type: gen.DeployTargetType(t.Type), RunsOn: gen.RunsOn(t.RunsOn),
		Config: cfg, StoredSecrets: names, GrantCount: grants, CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt}, nil
}

func (s *Server) targetsOut(ctx context.Context, rows []sqlcgen.DeployTarget) ([]gen.DeployTarget, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	counts, err := s.queries().DeployTargetGrantCounts(ctx, ids)
	if err != nil {
		return nil, err
	}
	cm := countMap(counts, func(r sqlcgen.DeployTargetGrantCountsRow) (uuid.UUID, int64) { return r.ID, r.Grants })
	out := make([]gen.DeployTarget, 0, len(rows))
	for _, r := range rows {
		t, err := s.targetOut(ctx, r, cm[r.ID])
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// targetAuditDetails is deploy_target.create/update/delete's fixed audit
// shape (Shared contracts Audit row): the target's identity only, never
// its config — a secret must never reach an audit record, and even the
// public config is no longer logged (it used to be).
func targetAuditDetails(t sqlcgen.DeployTarget) map[string]any {
	return map[string]any{"targetId": t.ID, "name": t.Name, "type": t.Type, "runsOn": t.RunsOn}
}

// mapTargetErr maps an error from s.d.Targets.Parse to a 422: the
// Unchanged-without-stored sentinel (targets.Registry.Parse wraps it
// "<field>: %w") becomes "<field> has no stored value"; a type's own
// delivery.FieldError (vault-kv, traefik) keeps its own field; anything
// else — a targetstest/product type's plain validation error — is a
// config-level 422 (never a raw internal error: every Parse failure here
// is caller input, not a server fault). t and raw are the target type and
// the caller's own raw config (batch 2 review, finding 3): a type's own
// Parse can echo a rejected value straight back into its error text (a
// pattern/format check, or a type's own hand-written validation), so every
// branch but the sentinel one — which never carries user input — is run
// through targets.Redact before it ever reaches the problem body. stored is
// the update's currently-stored secrets (final review, finding 2): on
// update, a secret sent as __unchanged__ or omitted is merged from storage
// before Parse runs, so a Parse error can just as easily echo a stored
// write-only secret as a raw request one — redact against the union of
// raw's own secret values (targets.Split) and stored's. stored is nil on
// create, where there is nothing stored yet. 0 disables Redact's length
// cap: this is a synchronous request/response body, not a stored/retried
// field with its own length limit.
func mapTargetErr(err error, t targets.Target, raw json.RawMessage, stored map[string]string) error {
	if errors.Is(err, targets.ErrUnchangedWithoutStored) {
		field := strings.TrimSuffix(err.Error(), ": "+targets.ErrUnchangedWithoutStored.Error())
		return unprocessable(field, fmt.Sprintf("%s has no stored value", field))
	}
	_, secrets, _ := targets.Split(t.Schema(), raw)
	// Redact only cares about map values, never keys (it builds one
	// args list from every value present) — but raw's own field name and
	// stored's are the same key, so merging them directly into one map
	// would let one silently overwrite the other (e.g. raw's
	// "__unchanged__" sentinel clobbering stored's real value) instead of
	// redacting both. Distinct prefixes per source keep every value.
	redact := make(map[string]string, len(secrets)+len(stored))
	for k, v := range secrets {
		redact["raw:"+k] = v
	}
	for k, v := range stored {
		redact["stored:"+k] = v
	}
	var fe *delivery.FieldError
	if errors.As(err, &fe) {
		return unprocessable(fe.Field, targets.Redact(errors.New(fe.Msg), redact, 0))
	}
	return unprocessable("config", targets.Redact(err, redact, 0))
}

// sameURLSet reports whether a and b hold the same URLs, order
// independent — validTarget's "did the URL set change" check.
func sameURLSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]bool, len(a))
	for _, u := range a {
		seen[u] = true
	}
	for _, u := range b {
		if !seen[u] {
			return false
		}
	}
	return true
}

// validatedTarget is validTarget's resolved shape, ready to store.
type validatedTarget struct {
	name       string
	side       targets.Mode
	public     []byte
	secretCfg  []byte   // sealed; nil when the config has no secrets
	secretKeys []string // names of the sealed fields, stored in plaintext
	needsKey   bool
}

// validTarget validates and canonicalizes a deploy target input against
// s.d.Targets (Shared contracts, Target operations row): the type is
// looked up (422 for unknown); the side is resolved (targets.ResolveSide
// on create — 422 "choose where this target runs" for an Either type with
// no runsOn, 422 naming the forced mode for a mismatch; old.RunsOn on
// update, 422 if the input's runsOn disagrees — type and runsOn are both
// immutable); any currently stored secrets are opened and handed to the
// registry's own Parse, which resolves __unchanged__/omitted/explicit-""
// against them; a URL that changed alongside a reused secret is refused
// ("re-enter the secret" — a stale secret must never silently carry over
// to a new destination); every URL is checked against the side's URL
// policy (server: the org's allowLoopbackUrls setting; agent: always
// allowed — an agent's own network is the operator's to reach); and the
// resolved secrets are sealed (nil when there are none). old is nil on
// create.
func (s *Server) validTarget(ctx context.Context, orgID uuid.UUID, in *gen.DeployTargetInput, old *sqlcgen.DeployTarget) (validatedTarget, error) {
	if in == nil {
		return validatedTarget{}, badRequest("missing body")
	}
	name, err := cleanName("name", in.Name)
	if err != nil {
		return validatedTarget{}, err
	}
	raw, err := json.Marshal(in.Config)
	if err != nil {
		return validatedTarget{}, badRequest("config is not a JSON object")
	}
	typ := string(in.Type)
	target, ok := s.d.Targets.Get(typ)
	if !ok {
		return validatedTarget{}, unprocessable("type", fmt.Sprintf("unknown deploy target type %q", in.Type))
	}
	requested := ""
	if in.RunsOn != nil {
		requested = string(*in.RunsOn)
	}
	var side targets.Mode
	if old == nil {
		side, err = targets.ResolveSide(target, requested)
		if err != nil {
			return validatedTarget{}, unprocessable("runsOn", err.Error())
		}
	} else {
		if old.Type != typ {
			return validatedTarget{}, unprocessable("type", "a deploy target's type cannot change")
		}
		side = targets.Mode(old.RunsOn)
		if requested != "" && targets.Mode(requested) != side {
			return validatedTarget{}, unprocessable("runsOn", "a deploy target's runsOn cannot change")
		}
	}
	stored, err := s.targetSecrets(ctx, old)
	if err != nil {
		return validatedTarget{}, err
	}
	cfg, reused, err := s.d.Targets.Parse(typ, raw, stored)
	if err != nil {
		return validatedTarget{}, mapTargetErr(err, target, raw, stored)
	}
	if old != nil && len(reused) > 0 {
		oldCfg, _, err := s.d.Targets.Parse(typ, old.Config, stored)
		if err != nil {
			return validatedTarget{}, mapTargetErr(err, target, old.Config, stored)
		}
		if !sameURLSet(oldCfg.URLs, cfg.URLs) {
			return validatedTarget{}, unprocessable("config", "re-enter the secret")
		}
	}
	if typ == deploy.TypeVaultKV {
		if err := s.checkVaultKVOrgPath(ctx, orgID, cfg.Public, old); err != nil {
			return validatedTarget{}, err
		}
	}
	allowLoopback := true
	if side == targets.Server {
		if allowLoopback, err = s.monitorAllowLoopback(ctx); err != nil {
			return validatedTarget{}, err
		}
	}
	for _, u := range cfg.URLs {
		// The URL itself is never echoed back (batch 2 review, finding 2):
		// it may carry userinfo or a query-string token a target's schema
		// does not mark "secret" at all (a plain "url" property), so the
		// problem body names the field, never the value.
		if err := httpx.CheckURL(u, allowLoopback); err != nil {
			return validatedTarget{}, unprocessable("config", "config: address not allowed")
		}
	}
	var secretCfg []byte
	if len(cfg.Secrets) > 0 {
		secretJSON, err := json.Marshal(cfg.Secrets)
		if err != nil {
			return validatedTarget{}, err
		}
		if secretCfg, err = s.d.Box.Seal(ctx, secretJSON); err != nil {
			return validatedTarget{}, err
		}
	}
	return validatedTarget{name: name, side: side, public: cfg.Public, secretCfg: secretCfg, secretKeys: storedSecretKeys(cfg.Secrets), needsKey: cfg.NeedsKey}, nil
}

// checkVaultKVOrgPath is S4's isolation gate: a principal without global
// delivery write may only set a vault-kv path that stays under
// certforge/<its org slug>/ (the one shared Vault has no per-org mounts). An
// unchanged stored path is grandfathered so an older target still saves.
func (s *Server) checkVaultKVOrgPath(ctx context.Context, orgID uuid.UUID, public []byte, old *sqlcgen.DeployTarget) error {
	if p, ok := authn.PrincipalFrom(ctx); ok && authz.Can(p, authz.ActionDeliveryWrite, nil) {
		return nil
	}
	if old != nil {
		var oldCfg, newCfg deploy.VaultKVConfig
		if json.Unmarshal(old.Config, &oldCfg) == nil && json.Unmarshal(public, &newCfg) == nil && oldCfg.Path == newCfg.Path {
			return nil
		}
	}
	org, err := s.queries().GetOrg(ctx, orgID)
	if err != nil {
		return err
	}
	if err := deploy.CheckOrgPath(public, org.Slug); err != nil {
		return &HTTPError{Status: http.StatusForbidden, Title: "Forbidden", Detail: "config.path: " + err.Error()}
	}
	return nil
}

// requireKeysExport requires keys:export when a server-run target's
// resolved config needs the certificate's private key (Shared contracts:
// DeployTargetInput's config needs keys:export on a server target whose
// KeyPolicy makes it need the key; re-checked on every create and update —
// generalizes the old vault-kv-only requireKeysExportForIncludeKey, and
// internal/agents.checkRefs runs the mirror check for a client-less grant
// on a NeedsKey target). An agent-run target never needs this: the agent,
// not this server, ever sees the key.
func (s *Server) requireKeysExport(ctx context.Context, orgID uuid.UUID, side targets.Mode, needsKey bool) error {
	if side != targets.Server || !needsKey {
		return nil
	}
	_, err := authorize(ctx, authz.ActionKeysExport, &orgID)
	return err
}

// ListDeployTargets returns an org's deploy targets.
func (s *Server) ListDeployTargets(ctx context.Context, r gen.ListDeployTargetsRequestObject) (gen.ListDeployTargetsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryRead, &r.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.queries().ListDeployTargets(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	items, err := s.targetsOut(ctx, rows)
	if err != nil {
		return nil, err
	}
	return gen.ListDeployTargets200JSONResponse(gen.DeployTargetList{Items: items}), nil
}

// GetDeployTarget returns one deploy target.
func (s *Server) GetDeployTarget(ctx context.Context, r gen.GetDeployTargetRequestObject) (gen.GetDeployTargetResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryRead, &r.OrgId); err != nil {
		return nil, err
	}
	t, err := s.queries().GetDeployTarget(ctx, sqlcgen.GetDeployTargetParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("deploy target %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	out, err := s.targetsOut(ctx, []sqlcgen.DeployTarget{t})
	if err != nil {
		return nil, err
	}
	return gen.GetDeployTarget200JSONResponse(out[0]), nil
}

// CreateDeployTarget adds a deploy target.
func (s *Server) CreateDeployTarget(ctx context.Context, r gen.CreateDeployTargetRequestObject) (gen.CreateDeployTargetResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	vt, err := s.validTarget(ctx, r.OrgId, r.Body, nil)
	if err != nil {
		return nil, err
	}
	if err := s.requireKeysExport(ctx, r.OrgId, vt.side, vt.needsKey); err != nil {
		return nil, err
	}
	t, err := s.queries().CreateDeployTarget(ctx, sqlcgen.CreateDeployTargetParams{OrgID: r.OrgId, Name: vt.name, Type: string(r.Body.Type),
		RunsOn: string(vt.side), Config: vt.public, SecretCfg: vt.secretCfg, StoredSecretKeys: vt.secretKeys})
	switch pgCode(err) {
	case pgUniqueViolation:
		return nil, conflict("A deploy target named %q exists in this org.", vt.name)
	case pgForeignKeyViolation:
		return nil, notFound("org %s", r.OrgId)
	}
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "deploy_target.create", ResourceType: "deploy_target", ResourceID: t.ID.String(), OrgID: &t.OrgID,
		Details: targetAuditDetails(t)})
	out, err := s.targetsOut(ctx, []sqlcgen.DeployTarget{t})
	if err != nil {
		return nil, err
	}
	return gen.CreateDeployTarget201JSONResponse(out[0]), nil
}

// UpdateDeployTarget replaces a deploy target's name and config; type and
// runsOn are immutable (validTarget).
func (s *Server) UpdateDeployTarget(ctx context.Context, r gen.UpdateDeployTargetRequestObject) (gen.UpdateDeployTargetResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	// DeployTargetForUpdate (FOR UPDATE, Task 1): validTarget below decides
	// whether to keep cur's stored secrets unchanged, so a concurrent
	// rewrap's CAS on secret_cfg must not be able to land between this read
	// and this update's own write (LockLayout's same convention).
	cur, err := q.DeployTargetForUpdate(ctx, sqlcgen.DeployTargetForUpdateParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("deploy target %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	vt, err := s.validTarget(ctx, r.OrgId, r.Body, &cur)
	if err != nil {
		return nil, err
	}
	// Gated whenever the resolved config needs the private key, whether it
	// was already needed or is only now turning true: an update from a
	// caller without keys:export must never be the thing that lets a
	// target start (or keep) writing private keys (controller ruling,
	// batch-5 review — delivery:write alone used to be enough to flip
	// this).
	if err := s.requireKeysExport(ctx, r.OrgId, vt.side, vt.needsKey); err != nil {
		return nil, err
	}
	// Final review finding 3: an update turning needsKey on is refused
	// (422) when any live server grant on this target has a certificate
	// with no stored key — the same has-key rule createServerGrant/
	// updateServerGrant already run (requireKeyIfNeeded), run here too so
	// the target itself can never end up needing a key none of its grants
	// can supply.
	if vt.needsKey {
		name, err := q.TargetKeylessGrantCertificate(ctx, &r.Id)
		if err == nil {
			return nil, unprocessable("config", fmt.Sprintf("certificate %q has no stored private key; this target needs one", name))
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return nil, err
		}
	}
	t, err := q.UpdateDeployTarget(ctx, sqlcgen.UpdateDeployTargetParams{Name: vt.name, Config: vt.public, SecretCfg: vt.secretCfg, StoredSecretKeys: vt.secretKeys, ID: r.Id, OrgID: r.OrgId})
	if pgCode(err) == pgUniqueViolation {
		return nil, conflict("A deploy target named %q exists in this org.", vt.name)
	}
	if err != nil {
		return nil, err
	}
	// S4: a changed mount or path must not make two live grants collide.
	if t.Type == deploy.TypeVaultKV && !bytes.Equal(cur.Config, t.Config) {
		if err := deploy.CheckServerGrantPaths(ctx, q, r.OrgId, t.ID); err != nil {
			return nil, mapErr(err)
		}
	}
	// Server grants on this target never go through agents.Resync (below),
	// so a target edit gets its own redeploy: mark pending and enqueue
	// certforge_server_deploy directly, in the same transaction.
	serverGrants, err := q.ServerGrantsUsingTarget(ctx, r.Id)
	if err != nil {
		return nil, err
	}
	for _, sg := range serverGrants {
		if err := s.d.Dispatcher.EnqueueTx(ctx, tx, q, sg.ID, sg.CurrentVersionID); err != nil {
			return nil, err
		}
	}
	nudge, err := s.d.Agents.Resync(ctx, q, agents.RefTarget, t.ID)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	nudge()
	s.audit(ctx, audit.Event{Action: "deploy_target.update", ResourceType: "deploy_target", ResourceID: t.ID.String(), OrgID: &t.OrgID,
		Details: targetAuditDetails(t)})
	out, err := s.targetsOut(ctx, []sqlcgen.DeployTarget{t})
	if err != nil {
		return nil, err
	}
	return gen.UpdateDeployTarget200JSONResponse(out[0]), nil
}

// DeleteDeployTarget removes a target no grant uses.
func (s *Server) DeleteDeployTarget(ctx context.Context, r gen.DeleteDeployTargetRequestObject) (gen.DeleteDeployTargetResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	q := s.queries()
	cur, err := q.GetDeployTarget(ctx, sqlcgen.GetDeployTargetParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("deploy target %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	deps, err := q.DeployTargetDependents(ctx, sqlcgen.DeployTargetDependentsParams{ID: &r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	if len(deps) > 0 {
		d := make([]dependent, len(deps))
		for i, x := range deps {
			d[i] = dependent{x.ClientName, x.CertificateName, x.Removing}
		}
		return nil, dependentsConflict("deploy target", d)
	}
	n, err := q.DeleteDeployTarget(ctx, sqlcgen.DeleteDeployTargetParams{ID: r.Id, OrgID: r.OrgId})
	if pgCode(err) == pgForeignKeyViolation {
		return nil, conflict("This deploy target was just granted; try again.")
	}
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, notFound("deploy target %s", r.Id)
	}
	s.audit(ctx, audit.Event{Action: "deploy_target.delete", ResourceType: "deploy_target", ResourceID: r.Id.String(), OrgID: &r.OrgId,
		Details: targetAuditDetails(cur)})
	return gen.DeleteDeployTarget204Response{}, nil
}

// ---- hooks ----

func hookOut(h sqlcgen.Hook, grants int) gen.Hook {
	return gen.Hook{Id: h.ID, OrgId: h.OrgID, Name: h.Name, Phase: gen.HookPhase(h.Phase), Argv: h.Argv,
		TimeoutSeconds: int(h.TimeoutSeconds), GrantCount: grants, CreatedAt: h.CreatedAt, UpdatedAt: h.UpdatedAt}
}

func (s *Server) hooksOut(ctx context.Context, rows []sqlcgen.Hook) ([]gen.Hook, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	counts, err := s.queries().HookGrantCounts(ctx, ids)
	if err != nil {
		return nil, err
	}
	cm := countMap(counts, func(r sqlcgen.HookGrantCountsRow) (uuid.UUID, int64) { return r.ID, r.Grants })
	out := make([]gen.Hook, 0, len(rows))
	for _, r := range rows {
		out = append(out, hookOut(r, cm[r.ID]))
	}
	return out, nil
}

func validHook(in *gen.HookInput) (string, int32, error) {
	if in == nil {
		return "", 0, badRequest("missing body")
	}
	name, err := cleanName("name", in.Name)
	if err != nil {
		return "", 0, err
	}
	timeout := 60
	if in.TimeoutSeconds != nil {
		timeout = *in.TimeoutSeconds
	}
	if err := delivery.ValidateHook(string(in.Phase), in.Argv, timeout); err != nil {
		return "", 0, mapDeliveryErr(err)
	}
	return name, int32(timeout), nil
}

// ListHooks returns an org's hooks.
func (s *Server) ListHooks(ctx context.Context, r gen.ListHooksRequestObject) (gen.ListHooksResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryRead, &r.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.queries().ListHooks(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	items, err := s.hooksOut(ctx, rows)
	if err != nil {
		return nil, err
	}
	return gen.ListHooks200JSONResponse(gen.HookList{Items: items}), nil
}

// GetHook returns one hook.
func (s *Server) GetHook(ctx context.Context, r gen.GetHookRequestObject) (gen.GetHookResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryRead, &r.OrgId); err != nil {
		return nil, err
	}
	h, err := s.queries().GetHook(ctx, sqlcgen.GetHookParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("hook %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	out, err := s.hooksOut(ctx, []sqlcgen.Hook{h})
	if err != nil {
		return nil, err
	}
	return gen.GetHook200JSONResponse(out[0]), nil
}

// CreateHook adds a hook.
func (s *Server) CreateHook(ctx context.Context, r gen.CreateHookRequestObject) (gen.CreateHookResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	name, timeout, err := validHook(r.Body)
	if err != nil {
		return nil, err
	}
	h, err := s.queries().CreateHook(ctx, sqlcgen.CreateHookParams{OrgID: r.OrgId, Name: name, Phase: string(r.Body.Phase), Argv: r.Body.Argv, TimeoutSeconds: timeout})
	switch pgCode(err) {
	case pgUniqueViolation:
		return nil, conflict("A hook named %q exists in this org.", name)
	case pgForeignKeyViolation:
		return nil, notFound("org %s", r.OrgId)
	}
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "hook.create", ResourceType: "hook", ResourceID: h.ID.String(), OrgID: &h.OrgID,
		Details: map[string]any{"name": h.Name, "phase": h.Phase, "argv": h.Argv, "timeoutSeconds": h.TimeoutSeconds}})
	return gen.CreateHook201JSONResponse(hookOut(h, 0)), nil
}

// UpdateHook replaces a hook.
func (s *Server) UpdateHook(ctx context.Context, r gen.UpdateHookRequestObject) (gen.UpdateHookResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	name, timeout, err := validHook(r.Body)
	if err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	cur, err := q.GetHook(ctx, sqlcgen.GetHookParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("hook %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	h, err := q.UpdateHook(ctx, sqlcgen.UpdateHookParams{Name: name, Phase: string(r.Body.Phase), Argv: r.Body.Argv, TimeoutSeconds: timeout, ID: r.Id, OrgID: r.OrgId})
	if pgCode(err) == pgUniqueViolation {
		return nil, conflict("A hook named %q exists in this org.", name)
	}
	if err != nil {
		return nil, err
	}
	nudge, err := s.d.Agents.Resync(ctx, q, agents.RefHook, h.ID)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	nudge()
	s.audit(ctx, audit.Event{Action: "hook.update", ResourceType: "hook", ResourceID: h.ID.String(), OrgID: &h.OrgID,
		Details: map[string]any{
			"before": map[string]any{"name": cur.Name, "phase": cur.Phase, "argv": cur.Argv, "timeoutSeconds": cur.TimeoutSeconds},
			"after":  map[string]any{"name": h.Name, "phase": h.Phase, "argv": h.Argv, "timeoutSeconds": h.TimeoutSeconds}}})
	out, err := s.hooksOut(ctx, []sqlcgen.Hook{h})
	if err != nil {
		return nil, err
	}
	return gen.UpdateHook200JSONResponse(out[0]), nil
}

// DeleteHook removes a hook no grant uses. It locks the hook row FOR UPDATE
// before re-checking dependents, inside one transaction with the delete:
// hook_ids has no FK, so a concurrent grant create/update that locks the
// same row FOR SHARE (agents.checkRefs) either commits first and is then
// seen by the dependents re-check, or blocks behind this delete and finds
// the hook gone.
func (s *Server) DeleteHook(ctx context.Context, r gen.DeleteHookRequestObject) (gen.DeleteHookResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	cur, err := q.LockHook(ctx, sqlcgen.LockHookParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("hook %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	deps, err := q.HookDependents(ctx, sqlcgen.HookDependentsParams{HookID: r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	if len(deps) > 0 {
		d := make([]dependent, len(deps))
		for i, x := range deps {
			d[i] = dependent{x.ClientName, x.CertificateName, x.Removing}
		}
		return nil, dependentsConflict("hook", d)
	}
	n, err := q.DeleteHook(ctx, sqlcgen.DeleteHookParams{ID: r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, notFound("hook %s", r.Id)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "hook.delete", ResourceType: "hook", ResourceID: r.Id.String(), OrgID: &r.OrgId,
		Details: map[string]any{"name": cur.Name}})
	return gen.DeleteHook204Response{}, nil
}
