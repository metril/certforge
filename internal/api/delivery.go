package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/deploy"
	"github.com/metril/certforge/internal/render"
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
	cur, err := q.GetLayout(ctx, sqlcgen.GetLayoutParams{ID: r.Id, OrgID: r.OrgId})
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

func targetOut(t sqlcgen.DeployTarget, grants int) (gen.DeployTarget, error) {
	cfg := map[string]interface{}{}
	if err := json.Unmarshal(t.Config, &cfg); err != nil {
		return gen.DeployTarget{}, err
	}
	return gen.DeployTarget{Id: t.ID, OrgId: t.OrgID, Name: t.Name, Type: gen.DeployTargetType(t.Type), RunsOn: gen.RunsOn(t.RunsOn),
		Config: cfg, GrantCount: grants, CreatedAt: t.CreatedAt, UpdatedAt: t.UpdatedAt}, nil
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
		t, err := targetOut(r, cm[r.ID])
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

// validTarget validates and canonicalizes a deploy target input, returning
// its name, config to store and derived runsOn: traefik goes through
// delivery.ParseTarget (agent-run), every other type is looked up in
// s.d.Deploy (server-run); an unknown type is 422. runsOn is always
// derived from the type (deploy.RunsOn), never taken from client input —
// DeployTargetInput has no runsOn field.
func (s *Server) validTarget(in *gen.DeployTargetInput) (name, runsOn string, cfg []byte, err error) {
	if in == nil {
		return "", "", nil, badRequest("missing body")
	}
	name, err = cleanName("name", in.Name)
	if err != nil {
		return "", "", nil, err
	}
	raw, err := json.Marshal(in.Config)
	if err != nil {
		return "", "", nil, badRequest("config is not a JSON object")
	}
	typ := string(in.Type)
	runsOn = deploy.RunsOn(typ)
	if typ == delivery.TargetTraefik {
		tc, err := delivery.ParseTarget(typ, raw)
		if err != nil {
			return "", "", nil, mapDeliveryErr(err)
		}
		cfg, err = json.Marshal(tc)
		return name, runsOn, cfg, err
	}
	cfg, ok, err := s.d.Deploy.ParseConfig(typ, raw)
	if !ok {
		return "", "", nil, unprocessable("type", fmt.Sprintf("unknown deploy target type %q", in.Type))
	}
	if err != nil {
		return "", "", nil, mapDeliveryErr(err)
	}
	return name, runsOn, cfg, nil
}

// requireKeysExportForIncludeKey requires keys:export when cfg's own
// includeKey field is true (Shared contracts: DeployTargetInput's
// includeKey needs keys:export; controller ruling extends this to every
// create and update, not only server-grant creation — an update is the
// only other place includeKey can ever become true). cfg is a target's
// already-canonicalized config (validTarget's own return), so includeKeyOf
// (internal/api/grants.go) applies unchanged.
func (s *Server) requireKeysExportForIncludeKey(ctx context.Context, orgID uuid.UUID, cfg []byte) error {
	includeKey, err := includeKeyOf(cfg)
	if err != nil {
		return err
	}
	if !includeKey {
		return nil
	}
	_, err = authorize(ctx, authz.ActionKeysExport, &orgID)
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
	name, runsOn, cfg, err := s.validTarget(r.Body)
	if err != nil {
		return nil, err
	}
	if err := s.requireKeysExportForIncludeKey(ctx, r.OrgId, cfg); err != nil {
		return nil, err
	}
	t, err := s.queries().CreateDeployTarget(ctx, sqlcgen.CreateDeployTargetParams{OrgID: r.OrgId, Name: name, Type: string(r.Body.Type), RunsOn: runsOn, Config: cfg})
	switch pgCode(err) {
	case pgUniqueViolation:
		return nil, conflict("A deploy target named %q exists in this org.", name)
	case pgForeignKeyViolation:
		return nil, notFound("org %s", r.OrgId)
	}
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "deploy_target.create", ResourceType: "deploy_target", ResourceID: t.ID.String(), OrgID: &t.OrgID,
		Details: map[string]any{"name": t.Name, "type": t.Type, "config": json.RawMessage(t.Config)}})
	out, err := s.targetsOut(ctx, []sqlcgen.DeployTarget{t})
	if err != nil {
		return nil, err
	}
	return gen.CreateDeployTarget201JSONResponse(out[0]), nil
}

// UpdateDeployTarget replaces a deploy target's name and config.
func (s *Server) UpdateDeployTarget(ctx context.Context, r gen.UpdateDeployTargetRequestObject) (gen.UpdateDeployTargetResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	name, _, cfg, err := s.validTarget(r.Body)
	if err != nil {
		return nil, err
	}
	// Gated whenever the new config sets includeKey true, whether it was
	// already true or is only now turning true: an update from a caller
	// without keys:export must never be the thing that lets a target start
	// (or keep) writing private keys to Vault (controller ruling, batch-5
	// review — delivery:write alone used to be enough to flip this).
	if err := s.requireKeysExportForIncludeKey(ctx, r.OrgId, cfg); err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	cur, err := q.GetDeployTarget(ctx, sqlcgen.GetDeployTargetParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("deploy target %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	if cur.Type != string(r.Body.Type) {
		return nil, unprocessable("type", "a deploy target's type cannot change")
	}
	t, err := q.UpdateDeployTarget(ctx, sqlcgen.UpdateDeployTargetParams{Name: name, Config: cfg, ID: r.Id, OrgID: r.OrgId})
	if pgCode(err) == pgUniqueViolation {
		return nil, conflict("A deploy target named %q exists in this org.", name)
	}
	if err != nil {
		return nil, err
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
		Details: map[string]any{"before": map[string]any{"name": cur.Name, "config": json.RawMessage(cur.Config)},
			"after": map[string]any{"name": t.Name, "config": json.RawMessage(t.Config)}}})
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
		Details: map[string]any{"name": cur.Name}})
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
