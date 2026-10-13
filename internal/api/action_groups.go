package api

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/actions"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/targets"
)

func actionGroupOut(g sqlcgen.ActionGroup, grants int) gen.ActionGroup {
	ids := g.ActionIds
	if ids == nil {
		ids = []uuid.UUID{}
	}
	return gen.ActionGroup{Id: g.ID, OrgId: g.OrgID, Name: g.Name, ActionIds: ids, GrantCount: grants, CreatedAt: g.CreatedAt, UpdatedAt: g.UpdatedAt}
}

func (s *Server) actionGroupsOut(ctx context.Context, rows []sqlcgen.ActionGroup) ([]gen.ActionGroup, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	counts, err := s.queries().ActionGroupGrantCounts(ctx, ids)
	if err != nil {
		return nil, err
	}
	cm := countMap(counts, func(r sqlcgen.ActionGroupGrantCountsRow) (uuid.UUID, int64) { return r.ID, r.Grants })
	out := make([]gen.ActionGroup, 0, len(rows))
	for _, r := range rows {
		out = append(out, actionGroupOut(r, cm[r.ID]))
	}
	return out, nil
}

// validGroup checks a group input: name, 1 to 32 actions, all in orgID. The
// actions are locked FOR SHARE so one cannot be deleted mid-write.
func validGroup(ctx context.Context, q *sqlcgen.Queries, orgID uuid.UUID, in *gen.ActionGroupInput) (string, []uuid.UUID, error) {
	if in == nil {
		return "", nil, badRequest("missing body")
	}
	name, err := cleanName("name", in.Name)
	if err != nil {
		return "", nil, err
	}
	switch {
	case len(in.ActionIds) == 0:
		return "", nil, unprocessable("actionIds", "a group needs at least one action")
	case len(in.ActionIds) > actions.MaxSteps:
		return "", nil, unprocessable("actionIds", "at most 32 actions per group")
	}
	uniq := slices.Clone(in.ActionIds)
	slices.SortFunc(uniq, func(a, b uuid.UUID) int { return strings.Compare(a.String(), b.String()) })
	uniq = slices.Compact(uniq)
	locked, err := q.LockActionsInOrg(ctx, sqlcgen.LockActionsInOrgParams{Ids: uniq, OrgID: orgID})
	if err != nil {
		return "", nil, err
	}
	have := map[uuid.UUID]bool{}
	for _, id := range locked {
		have[id] = true
	}
	for i, id := range in.ActionIds {
		if !have[id] {
			return "", nil, unprocessable(fmt.Sprintf("actionIds[%d]", i), fmt.Sprintf("action %s is not in this org", id))
		}
	}
	return name, in.ActionIds, nil
}

// ListActionGroups returns an org's action groups.
func (s *Server) ListActionGroups(ctx context.Context, r gen.ListActionGroupsRequestObject) (gen.ListActionGroupsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryRead, &r.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.queries().ListActionGroups(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	items, err := s.actionGroupsOut(ctx, rows)
	if err != nil {
		return nil, err
	}
	return gen.ListActionGroups200JSONResponse(gen.ActionGroupList{Items: items}), nil
}

// GetActionGroup returns one action group.
func (s *Server) GetActionGroup(ctx context.Context, r gen.GetActionGroupRequestObject) (gen.GetActionGroupResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryRead, &r.OrgId); err != nil {
		return nil, err
	}
	g, err := s.queries().GetActionGroup(ctx, sqlcgen.GetActionGroupParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("action group %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	out, err := s.actionGroupsOut(ctx, []sqlcgen.ActionGroup{g})
	if err != nil {
		return nil, err
	}
	return gen.GetActionGroup200JSONResponse(out[0]), nil
}

// CreateActionGroup adds an action group.
func (s *Server) CreateActionGroup(ctx context.Context, r gen.CreateActionGroupRequestObject) (gen.CreateActionGroupResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	name, ids, err := validGroup(ctx, q, r.OrgId, r.Body)
	if err != nil {
		return nil, err
	}
	g, err := q.CreateActionGroup(ctx, sqlcgen.CreateActionGroupParams{OrgID: r.OrgId, Name: name, ActionIds: ids})
	switch pgCode(err) {
	case pgUniqueViolation:
		return nil, conflict("An action group named %q exists in this org.", name)
	case pgForeignKeyViolation:
		return nil, notFound("org %s", r.OrgId)
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "action_group.create", ResourceType: "action_group", ResourceID: g.ID.String(), OrgID: &g.OrgID,
		Details: map[string]any{"name": g.Name, "actionIds": g.ActionIds}})
	return gen.CreateActionGroup201JSONResponse(actionGroupOut(g, 0)), nil
}

// UpdateActionGroup replaces an action group.
func (s *Server) UpdateActionGroup(ctx context.Context, r gen.UpdateActionGroupRequestObject) (gen.UpdateActionGroupResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	cur, err := q.LockActionGroup(ctx, sqlcgen.LockActionGroupParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("action group %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	name, ids, err := validGroup(ctx, q, r.OrgId, r.Body)
	if err != nil {
		return nil, err
	}
	if err := groupFitsGrants(ctx, q, r.Id, ids); err != nil {
		return nil, err
	}
	g, err := q.UpdateActionGroup(ctx, sqlcgen.UpdateActionGroupParams{Name: name, ActionIds: ids, ID: r.Id, OrgID: r.OrgId})
	if pgCode(err) == pgUniqueViolation {
		return nil, conflict("An action group named %q exists in this org.", name)
	}
	if err != nil {
		return nil, err
	}
	nudge, err := s.d.Agents.Resync(ctx, q, agents.RefGroup, g.ID)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	nudge()
	s.audit(ctx, audit.Event{Action: "action_group.update", ResourceType: "action_group", ResourceID: g.ID.String(), OrgID: &g.OrgID,
		Details: map[string]any{
			"before": map[string]any{"name": cur.Name, "actionIds": cur.ActionIds},
			"after":  map[string]any{"name": g.Name, "actionIds": g.ActionIds}}})
	out, err := s.actionGroupsOut(ctx, []sqlcgen.ActionGroup{g})
	if err != nil {
		return nil, err
	}
	return gen.UpdateActionGroup200JSONResponse(out[0]), nil
}

// DeleteActionGroup removes a group no grant step uses.
func (s *Server) DeleteActionGroup(ctx context.Context, r gen.DeleteActionGroupRequestObject) (gen.DeleteActionGroupResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	cur, err := q.LockActionGroup(ctx, sqlcgen.LockActionGroupParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("action group %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	deps, err := q.ActionGroupDependents(ctx, sqlcgen.ActionGroupDependentsParams{GroupID: r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	if len(deps) > 0 {
		d := make([]dependent, len(deps))
		for i, x := range deps {
			d[i] = dependent{x.OwnerName, x.CertificateName, x.Removing}
		}
		return nil, dependentsConflict("action group", d)
	}
	n, err := q.DeleteActionGroup(ctx, sqlcgen.DeleteActionGroupParams{ID: r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, notFound("action group %s", r.Id)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "action_group.delete", ResourceType: "action_group", ResourceID: r.Id.String(), OrgID: &r.OrgId,
		Details: map[string]any{"name": cur.Name}})
	return gen.DeleteActionGroup204Response{}, nil
}

// groupFitsGrants refuses a member list that a live grant using the group
// could not run: an agent-only action in a server grant's group, or a
// server-only one in a client grant's.
func groupFitsGrants(ctx context.Context, q *sqlcgen.Queries, groupID uuid.UUID, ids []uuid.UUID) error {
	sides, err := q.LiveGrantSidesUsingActionGroup(ctx, groupID)
	if err != nil || len(sides) == 0 {
		return err
	}
	rows, err := q.ActionsByIDs(ctx, ids)
	if err != nil {
		return err
	}
	refs := make([]actions.ActionRef, 0, len(rows))
	for _, a := range rows {
		ref := actions.ActionRef{ID: a.ID}
		if k, ok := actions.Default.Get(a.Kind); ok {
			ref.RunsOn = k.RunsOn()
		}
		refs = append(refs, ref)
	}
	for _, server := range sides {
		mode, who := targets.Agent, "client"
		if server {
			mode, who = targets.Server, "server"
		}
		if actions.RunsOnMismatch(refs, mode) >= 0 {
			return conflict("This group is used by %s grants, and an action in it cannot run there.", who)
		}
	}
	return nil
}
