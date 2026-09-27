package api

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
)

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
		out = append(out, delivery.OutputFile{Path: f.Path, Format: string(f.Format), Parts: parts, Owner: f.Owner, Group: f.Group, Mode: f.Mode})
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
		out = append(out, gen.OutputFile{Path: f.Path, Format: gen.OutputFormat(f.Format), Parts: parts, Owner: f.Owner, Group: f.Group, Mode: f.Mode})
	}
	// ExtraCertificateIds is required and non-nullable; Task 5 fills it (and
	// PasswordSet) for real, but an empty slice must go out now, not the nil
	// slice's JSON null.
	return gen.Layout{Id: l.ID, OrgId: l.OrgID, Name: l.Name, Files: out, GrantCount: grants,
		ExtraCertificateIds: []uuid.UUID{}, CreatedAt: l.CreatedAt, UpdatedAt: l.UpdatedAt}, nil
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

func validLayout(in *gen.LayoutInput) (string, []byte, error) {
	if in == nil {
		return "", nil, badRequest("missing body")
	}
	name, err := cleanName("name", in.Name)
	if err != nil {
		return "", nil, err
	}
	files := layoutFilesIn(in.Files)
	if err := delivery.ValidateFiles(files); err != nil {
		return "", nil, mapDeliveryErr(err)
	}
	for i := range files {
		if len(files[i].Mode) == 3 {
			files[i].Mode = "0" + files[i].Mode
		}
	}
	b, err := json.Marshal(files)
	return name, b, err
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

// CreateLayout adds a layout.
func (s *Server) CreateLayout(ctx context.Context, r gen.CreateLayoutRequestObject) (gen.CreateLayoutResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	name, files, err := validLayout(r.Body)
	if err != nil {
		return nil, err
	}
	l, err := s.queries().CreateLayout(ctx, sqlcgen.CreateLayoutParams{OrgID: r.OrgId, Name: name, Files: files})
	switch pgCode(err) {
	case pgUniqueViolation:
		return nil, conflict("A layout named %q exists in this org.", name)
	case pgForeignKeyViolation:
		return nil, notFound("org %s", r.OrgId)
	}
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "layout.create", ResourceType: "layout", ResourceID: l.ID.String(), OrgID: &l.OrgID,
		Details: map[string]any{"name": l.Name, "files": json.RawMessage(l.Files)}})
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
	name, files, err := validLayout(r.Body)
	if err != nil {
		return nil, err
	}
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
	l, err := q.UpdateLayout(ctx, sqlcgen.UpdateLayoutParams{Name: name, Files: files, ID: r.Id, OrgID: r.OrgId})
	if pgCode(err) == pgUniqueViolation {
		return nil, conflict("A layout named %q exists in this org.", name)
	}
	if err != nil {
		return nil, err
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
		Details: map[string]any{"before": map[string]any{"name": cur.Name, "files": json.RawMessage(cur.Files)},
			"after": map[string]any{"name": l.Name, "files": json.RawMessage(l.Files)}}})
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

func validTarget(in *gen.DeployTargetInput) (string, []byte, error) {
	if in == nil {
		return "", nil, badRequest("missing body")
	}
	name, err := cleanName("name", in.Name)
	if err != nil {
		return "", nil, err
	}
	raw, err := json.Marshal(in.Config)
	if err != nil {
		return "", nil, badRequest("config is not a JSON object")
	}
	cfg, err := delivery.ParseTarget(string(in.Type), raw)
	if err != nil {
		return "", nil, mapDeliveryErr(err)
	}
	b, err := json.Marshal(cfg)
	return name, b, err
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
	name, cfg, err := validTarget(r.Body)
	if err != nil {
		return nil, err
	}
	t, err := s.queries().CreateDeployTarget(ctx, sqlcgen.CreateDeployTargetParams{OrgID: r.OrgId, Name: name, Type: string(r.Body.Type), Config: cfg})
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
	name, cfg, err := validTarget(r.Body)
	if err != nil {
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
