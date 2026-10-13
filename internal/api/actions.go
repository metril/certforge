package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/actions"
	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/targets"
)

// unchangedSentinel is the secret value that keeps the stored one, as for
// deploy targets.
const unchangedSentinel = "__unchanged__"

// actionSecretFields returns the top-level properties of schema marked
// "secret": true, mapped to whether they are strings (else JSON values).
func actionSecretFields(schema json.RawMessage) map[string]bool {
	var doc struct {
		Properties map[string]struct {
			Secret bool `json:"secret"`
			Type   any  `json:"type"`
		} `json:"properties"`
	}
	_ = json.Unmarshal(schema, &doc)
	out := map[string]bool{}
	for k, p := range doc.Properties {
		if p.Secret {
			t, _ := p.Type.(string)
			out[k] = t == "string"
		}
	}
	return out
}

// actionSecrets opens an action's sealed secret_cfg.
func (s *Server) actionSecrets(ctx context.Context, sealed []byte) (map[string]string, error) {
	if len(sealed) == 0 {
		return map[string]string{}, nil
	}
	pt, err := s.d.Box.Open(ctx, sealed)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func actionOut(a sqlcgen.Action, grants int, secretKeys []string) gen.Action {
	cfg := map[string]interface{}{}
	_ = json.Unmarshal(a.Config, &cfg)
	runsOn := gen.RunsOn("server")
	if k, ok := actions.Default.Get(a.Kind); ok && k.RunsOn() == targets.Agent {
		runsOn = "agent"
	}
	if secretKeys == nil {
		secretKeys = []string{}
	}
	return gen.Action{Id: a.ID, OrgId: a.OrgID, Name: a.Name, Kind: gen.ActionKind(a.Kind), Phase: gen.ActionPhase(a.Phase), RunsOn: runsOn,
		Config: cfg, SecretKeys: secretKeys, TimeoutSeconds: int(a.TimeoutSeconds), Optional: a.Optional, GrantCount: grants,
		CreatedAt: a.CreatedAt, UpdatedAt: a.UpdatedAt}
}

func (s *Server) actionsOut(ctx context.Context, rows []sqlcgen.Action) ([]gen.Action, error) {
	ids := make([]uuid.UUID, len(rows))
	for i, r := range rows {
		ids[i] = r.ID
	}
	counts, err := s.queries().ActionGrantCounts(ctx, ids)
	if err != nil {
		return nil, err
	}
	cm := countMap(counts, func(r sqlcgen.ActionGrantCountsRow) (uuid.UUID, int64) { return r.ID, r.Grants })
	out := make([]gen.Action, 0, len(rows))
	for _, r := range rows {
		secrets, err := s.actionSecrets(ctx, r.SecretCfg)
		if err != nil {
			return nil, err
		}
		out = append(out, actionOut(r, cm[r.ID], storedSecretKeys(secrets)))
	}
	return out, nil
}

// validatedAction is an action input resolved and ready to store.
type validatedAction struct {
	name, kind, phase string
	public            []byte
	sealed            []byte
	timeout           int32
	optional          bool
	runsOn            targets.Mode
}

// validAction validates an action input. old, when set, is the stored action
// whose secrets a "__unchanged__" or omitted secret field keeps.
func (s *Server) validAction(ctx context.Context, q *sqlcgen.Queries, orgID uuid.UUID, in *gen.ActionInput, old *sqlcgen.Action) (validatedAction, error) {
	if in == nil {
		return validatedAction{}, badRequest("missing body")
	}
	name, err := cleanName("name", in.Name)
	if err != nil {
		return validatedAction{}, err
	}
	kind, ok := actions.Default.Get(string(in.Kind))
	if !ok {
		return validatedAction{}, unprocessable("kind", fmt.Sprintf("unknown action kind %q", in.Kind))
	}
	if in.Phase != gen.ActionPhasePreDeploy && in.Phase != gen.ActionPhasePostDeploy {
		return validatedAction{}, unprocessable("phase", "phase must be pre_deploy or post_deploy")
	}
	timeout := 60
	if in.TimeoutSeconds != nil {
		timeout = *in.TimeoutSeconds
	}
	if timeout < 1 || timeout > 3600 {
		return validatedAction{}, unprocessable("timeoutSeconds", "timeoutSeconds must be 1 to 3600")
	}
	cfg := map[string]json.RawMessage{}
	if in.Config != nil {
		b, err := json.Marshal(in.Config)
		if err != nil {
			return validatedAction{}, badRequest("config is not a JSON object")
		}
		if err := json.Unmarshal(b, &cfg); err != nil {
			return validatedAction{}, badRequest("config is not a JSON object")
		}
	}
	// Merge kept secrets back before validation.
	var stored map[string]string
	if old != nil && old.Kind == string(in.Kind) {
		if stored, err = s.actionSecrets(ctx, old.SecretCfg); err != nil {
			return validatedAction{}, err
		}
	}
	for field, isString := range actionSecretFields(kind.Schema()) {
		v, present := cfg[field]
		var str string
		keep := !present || (json.Unmarshal(v, &str) == nil && str == unchangedSentinel)
		if !keep {
			continue
		}
		prev, have := stored[field]
		switch {
		case have && isString:
			cfg[field], _ = json.Marshal(prev)
		case have:
			cfg[field] = json.RawMessage(prev)
		case present:
			return validatedAction{}, unprocessable("config."+field, field+" has no stored value")
		}
	}
	raw, _ := json.Marshal(cfg)
	parsed, err := kind.Parse(raw)
	if err != nil {
		var fe *delivery.FieldError
		if errors.As(err, &fe) {
			f := fe.Field
			if !strings.HasPrefix(f, "config") {
				f = "config." + f
			}
			return validatedAction{}, unprocessable(f, fe.Msg)
		}
		return validatedAction{}, unprocessable("config", err.Error())
	}
	var refs struct {
		TargetID  string `json:"targetId"`
		ChannelID string `json:"channelId"`
	}
	_ = json.Unmarshal(parsed.Public, &refs)
	if refs.TargetID != "" {
		id, _ := uuid.Parse(refs.TargetID)
		t, err := q.GetDeployTarget(ctx, sqlcgen.GetDeployTargetParams{ID: id, OrgID: orgID})
		if errors.Is(err, pgx.ErrNoRows) {
			return validatedAction{}, unprocessable("config.targetId", fmt.Sprintf("deploy target %s is not in this org", id))
		} else if err != nil {
			return validatedAction{}, err
		}
		if types := kind.TargetTypes(); !slices.Contains(types, t.Type) {
			return validatedAction{}, unprocessable("config.targetId", fmt.Sprintf("a %s action needs %s target", kind.Code(), postTargetPhrase(types)))
		}
	}
	if refs.ChannelID != "" {
		id, _ := uuid.Parse(refs.ChannelID)
		if _, err := q.GetOrgNotificationChannel(ctx, sqlcgen.GetOrgNotificationChannelParams{ID: id, OrgID: orgID}); errors.Is(err, pgx.ErrNoRows) {
			return validatedAction{}, unprocessable("config.channelId", fmt.Sprintf("notification channel %s is not in this org", id))
		} else if err != nil {
			return validatedAction{}, err
		}
	}
	var sealed []byte
	if len(parsed.Secrets) > 0 {
		b, _ := json.Marshal(parsed.Secrets)
		if sealed, err = s.d.Box.Seal(ctx, b); err != nil {
			return validatedAction{}, err
		}
	}
	return validatedAction{name: name, kind: kind.Code(), phase: string(in.Phase), public: parsed.Public, sealed: sealed,
		timeout: int32(timeout), optional: in.Optional != nil && *in.Optional, runsOn: kind.RunsOn()}, nil
}

// actionAudit is an action's audit shape: never the secrets.
func actionAudit(a sqlcgen.Action) map[string]any {
	return map[string]any{"name": a.Name, "kind": a.Kind, "phase": a.Phase, "config": json.RawMessage(a.Config),
		"timeoutSeconds": a.TimeoutSeconds, "optional": a.Optional}
}

// ListActions returns an org's actions.
func (s *Server) ListActions(ctx context.Context, r gen.ListActionsRequestObject) (gen.ListActionsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryRead, &r.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.queries().ListActions(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	items, err := s.actionsOut(ctx, rows)
	if err != nil {
		return nil, err
	}
	return gen.ListActions200JSONResponse(gen.ActionList{Items: items}), nil
}

// GetAction returns one action.
func (s *Server) GetAction(ctx context.Context, r gen.GetActionRequestObject) (gen.GetActionResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryRead, &r.OrgId); err != nil {
		return nil, err
	}
	a, err := s.queries().GetAction(ctx, sqlcgen.GetActionParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("action %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	out, err := s.actionsOut(ctx, []sqlcgen.Action{a})
	if err != nil {
		return nil, err
	}
	return gen.GetAction200JSONResponse(out[0]), nil
}

// CreateAction adds an action.
func (s *Server) CreateAction(ctx context.Context, r gen.CreateActionRequestObject) (gen.CreateActionResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	v, err := s.validAction(ctx, s.queries(), r.OrgId, r.Body, nil)
	if err != nil {
		return nil, err
	}
	a, err := s.queries().CreateAction(ctx, sqlcgen.CreateActionParams{OrgID: r.OrgId, Name: v.name, Kind: v.kind, Phase: v.phase,
		Config: v.public, SecretCfg: v.sealed, TimeoutSeconds: v.timeout, Optional: v.optional})
	switch pgCode(err) {
	case pgUniqueViolation:
		return nil, conflict("An action named %q exists in this org.", v.name)
	case pgForeignKeyViolation:
		return nil, notFound("org %s", r.OrgId)
	}
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "action.create", ResourceType: "action", ResourceID: a.ID.String(), OrgID: &a.OrgID, Details: actionAudit(a)})
	out, err := s.actionsOut(ctx, []sqlcgen.Action{a})
	if err != nil {
		return nil, err
	}
	return gen.CreateAction201JSONResponse(out[0]), nil
}

// UpdateAction replaces an action.
func (s *Server) UpdateAction(ctx context.Context, r gen.UpdateActionRequestObject) (gen.UpdateActionResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	cur, err := q.LockAction(ctx, sqlcgen.LockActionParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("action %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	v, err := s.validAction(ctx, q, r.OrgId, r.Body, &cur)
	if err != nil {
		return nil, err
	}
	// Moving an action to the other side would strand the grants that use it.
	if oldKind, ok := actions.Default.Get(cur.Kind); ok && oldKind.RunsOn() != v.runsOn {
		deps, err := q.ActionDependents(ctx, sqlcgen.ActionDependentsParams{ActionID: r.Id, OrgID: r.OrgId})
		if err != nil {
			return nil, err
		}
		if len(deps) > 0 {
			return nil, actionDependentsConflict("action", deps)
		}
	}
	a, err := q.UpdateAction(ctx, sqlcgen.UpdateActionParams{Name: v.name, Kind: v.kind, Phase: v.phase, Config: v.public, SecretCfg: v.sealed,
		TimeoutSeconds: v.timeout, Optional: v.optional, ID: r.Id, OrgID: r.OrgId})
	if pgCode(err) == pgUniqueViolation {
		return nil, conflict("An action named %q exists in this org.", v.name)
	}
	if err != nil {
		return nil, err
	}
	nudge, err := s.d.Agents.Resync(ctx, q, agents.RefHook, a.ID)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	nudge()
	s.audit(ctx, audit.Event{Action: "action.update", ResourceType: "action", ResourceID: a.ID.String(), OrgID: &a.OrgID,
		Details: map[string]any{"before": actionAudit(cur), "after": actionAudit(a)}})
	out, err := s.actionsOut(ctx, []sqlcgen.Action{a})
	if err != nil {
		return nil, err
	}
	return gen.UpdateAction200JSONResponse(out[0]), nil
}

// actionDependentsConflict is the 409 for an action still named by grant
// steps or groups.
func actionDependentsConflict(noun string, deps []sqlcgen.ActionDependentsRow) error {
	var parts []string
	for i, d := range deps {
		if i == 5 {
			parts = append(parts, "and more")
			break
		}
		p := "group " + d.OwnerName
		if d.DependentKind == "grant" {
			p = d.OwnerName + "/" + d.CertificateName
			if d.Removing {
				p += " (removal pending)"
			}
		}
		parts = append(parts, p)
	}
	return conflict("This %s is used by: %s. Remove it from those grants and groups first.", noun, strings.Join(parts, ", "))
}

// DeleteAction removes an action no grant or group uses.
func (s *Server) DeleteAction(ctx context.Context, r gen.DeleteActionRequestObject) (gen.DeleteActionResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeliveryWrite, &r.OrgId); err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	cur, err := q.LockAction(ctx, sqlcgen.LockActionParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("action %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	deps, err := q.ActionDependents(ctx, sqlcgen.ActionDependentsParams{ActionID: r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	if len(deps) > 0 {
		return nil, actionDependentsConflict("action", deps)
	}
	n, err := q.DeleteAction(ctx, sqlcgen.DeleteActionParams{ID: r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, notFound("action %s", r.Id)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "action.delete", ResourceType: "action", ResourceID: r.Id.String(), OrgID: &r.OrgId,
		Details: map[string]any{"name": cur.Name, "kind": cur.Kind}})
	return gen.DeleteAction204Response{}, nil
}

// actionMetaEntries lists the registered action kinds for GET /meta/schemas.
func actionMetaEntries() ([]gen.ActionSchemaEntry, error) {
	kinds := actions.Default.All()
	out := make([]gen.ActionSchemaEntry, 0, len(kinds))
	for _, k := range kinds {
		var schema map[string]interface{}
		if err := json.Unmarshal(k.Schema(), &schema); err != nil {
			return nil, fmt.Errorf("action kind %s schema: %w", k.Code(), err)
		}
		if order := propertyOrder(k.Schema()); len(order) > 0 {
			schema["x-order"] = order
		}
		types := append([]string{}, k.TargetTypes()...)
		sort.Strings(types)
		runsOn := gen.RunsOn(k.RunsOn())
		out = append(out, gen.ActionSchemaEntry{Code: k.Code(), Name: k.Name(), Schema: schema, RunsOn: runsOn,
			PhaseHint: gen.ActionSchemaEntryPhaseHint(k.PhaseHint()), TargetTypes: types})
	}
	return out, nil
}
