package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/targets"
)

// credentialOut builds the response for a stored credential: the public
// fields and the names of the stored secrets, never a secret value.
func credentialOut(c sqlcgen.DeployCredential, usedBy int64) (gen.DeployCredential, error) {
	cfg := map[string]interface{}{}
	if len(c.Public) > 0 {
		if err := json.Unmarshal(c.Public, &cfg); err != nil {
			return gen.DeployCredential{}, err
		}
	}
	keys := c.StoredSecretKeys
	if keys == nil {
		keys = []string{}
	}
	return gen.DeployCredential{Id: c.ID, OrgId: ptr(c.OrgID), Name: c.Name, Kind: gen.DeployCredentialKind(c.Kind), Config: cfg,
		StoredSecrets: &keys, UsedBy: ptr(int(usedBy)), CreatedAt: ptr(c.CreatedAt), UpdatedAt: ptr(c.UpdatedAt)}, nil
}

// sealCredentialSecrets seals the secret map (an empty map is sealed too:
// the column is NOT NULL).
func (s *Server) sealCredentialSecrets(ctx context.Context, secrets map[string]string) ([]byte, error) {
	b, err := json.Marshal(secrets)
	if err != nil {
		return nil, err
	}
	return s.d.Box.Seal(ctx, b)
}

func (s *Server) openCredentialSecrets(ctx context.Context, sealed []byte) (map[string]string, error) {
	out := map[string]string{}
	if len(sealed) == 0 {
		return out, nil
	}
	pt, err := s.d.Box.Open(ctx, sealed)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(pt, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListDeployCredentials returns the org's deploy credentials by name, without secrets.
func (s *Server) ListDeployCredentials(ctx context.Context, r gen.ListDeployCredentialsRequestObject) (gen.ListDeployCredentialsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeployCredsRead, &r.OrgId); err != nil {
		return nil, err
	}
	q := s.queries()
	rows, err := q.ListDeployCredentials(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	counts, err := q.CountDeployCredentialUsersByOrg(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	used := make(map[uuid.UUID]int64, len(counts))
	for _, c := range counts {
		used[c.ID] = c.Users
	}
	out := make(gen.ListDeployCredentials200JSONResponse, 0, len(rows))
	for _, row := range rows {
		o, err := credentialOut(row, used[row.ID])
		if err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, nil
}

// GetDeployCredential returns one credential of the org, without secrets.
func (s *Server) GetDeployCredential(ctx context.Context, r gen.GetDeployCredentialRequestObject) (gen.GetDeployCredentialResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeployCredsRead, &r.OrgId); err != nil {
		return nil, err
	}
	q := s.queries()
	row, err := q.GetDeployCredential(ctx, sqlcgen.GetDeployCredentialParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("deploy credential %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	n, err := q.CountDeployCredentialUsers(ctx, sqlcgen.CountDeployCredentialUsersParams{CredentialID: &r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	out, err := credentialOut(row, n)
	if err != nil {
		return nil, err
	}
	return gen.GetDeployCredential200JSONResponse(out), nil
}

// validCredentialConfig validates the full config (secrets included) against
// the kind's schema and splits it. The config must not hold __unchanged__.
func validCredentialConfig(kind string, cfg map[string]interface{}) (json.RawMessage, map[string]string, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, nil, badRequest("config is not a JSON object")
	}
	if err := targets.ValidateCredential(kind, raw); err != nil {
		return nil, nil, unprocessable("config", err.Error())
	}
	pub, sec, err := targets.SplitCredential(kind, raw)
	if err != nil {
		return nil, nil, unprocessable("config", err.Error())
	}
	return pub, sec, nil
}

func secretKeysSorted(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// CreateDeployCredential validates config against the kind's schema and stores it.
func (s *Server) CreateDeployCredential(ctx context.Context, r gen.CreateDeployCredentialRequestObject) (gen.CreateDeployCredentialResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeployCredsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, badRequest("missing body")
	}
	name, err := cleanName("name", r.Body.Name)
	if err != nil {
		return nil, err
	}
	kind := string(r.Body.Kind)
	if _, ok := targets.KindSchema(kind); !ok {
		return nil, unprocessable("kind", fmt.Sprintf("unknown credential kind %q", kind))
	}
	for k, v := range r.Body.Config {
		if str, ok := v.(string); ok && str == targets.Unchanged {
			return nil, unprocessable("config", k+" cannot be "+targets.Unchanged+" on create")
		}
	}
	pub, sec, err := validCredentialConfig(kind, r.Body.Config)
	if err != nil {
		return nil, err
	}
	sealed, err := s.sealCredentialSecrets(ctx, sec)
	if err != nil {
		return nil, err
	}
	row, err := s.queries().CreateDeployCredential(ctx, sqlcgen.CreateDeployCredentialParams{OrgID: r.OrgId, Name: name, Kind: kind,
		Public: pub, SecretCfg: sealed, StoredSecretKeys: secretKeysSorted(sec)})
	switch pgCode(err) {
	case pgUniqueViolation:
		return nil, conflict("A deploy credential named %q exists in this org.", name)
	case pgForeignKeyViolation:
		return nil, notFound("org %s", r.OrgId)
	}
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "deploy_credential.create", ResourceType: "deploy_credential", ResourceID: row.ID.String(), OrgID: &r.OrgId,
		Details: map[string]any{"name": row.Name, "kind": row.Kind}})
	out, err := credentialOut(row, 0)
	if err != nil {
		return nil, err
	}
	return gen.CreateDeployCredential201JSONResponse(out), nil
}

// UpdateDeployCredential replaces a credential's name and config; the kind
// cannot change, and a secret field set to __unchanged__ keeps its stored
// value. Dependent agent targets are re-synced in the same transaction (the
// files and version are unchanged, so no agent reinstalls anything); server
// deploys read the new value next time they run.
func (s *Server) UpdateDeployCredential(ctx context.Context, r gen.UpdateDeployCredentialRequestObject) (gen.UpdateDeployCredentialResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeployCredsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, badRequest("missing body")
	}
	name, err := cleanName("name", r.Body.Name)
	if err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	cur, err := q.LockDeployCredential(ctx, sqlcgen.LockDeployCredentialParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("deploy credential %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	stored, err := s.openCredentialSecrets(ctx, cur.SecretCfg)
	if err != nil {
		return nil, err
	}
	cfg := make(map[string]interface{}, len(r.Body.Config))
	for k, v := range r.Body.Config {
		cfg[k] = v
	}
	for _, k := range targets.SecretFields(cur.Kind) {
		if str, ok := cfg[k].(string); ok && str == targets.Unchanged {
			old, ok := stored[k]
			if !ok {
				return nil, unprocessable(k, k+" has no stored value")
			}
			cfg[k] = old
		}
	}
	pub, sec, err := validCredentialConfig(cur.Kind, cfg)
	if err != nil {
		return nil, err
	}
	sealed, err := s.sealCredentialSecrets(ctx, sec)
	if err != nil {
		return nil, err
	}
	row, err := q.UpdateDeployCredential(ctx, sqlcgen.UpdateDeployCredentialParams{ID: r.Id, OrgID: r.OrgId, Name: name, Public: pub,
		SecretCfg: sealed, StoredSecretKeys: secretKeysSorted(sec)})
	if pgCode(err) == pgUniqueViolation {
		return nil, conflict("A deploy credential named %q exists in this org.", name)
	}
	if err != nil {
		return nil, err
	}
	nudge, err := s.d.Agents.Resync(ctx, q, agents.RefCredential, r.Id)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	n, err := q.CountDeployCredentialUsers(ctx, sqlcgen.CountDeployCredentialUsersParams{CredentialID: &r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	nudge()
	s.audit(ctx, audit.Event{Action: "deploy_credential.update", ResourceType: "deploy_credential", ResourceID: row.ID.String(), OrgID: &r.OrgId,
		Details: map[string]any{"name": row.Name, "kind": row.Kind}})
	out, err := credentialOut(row, n)
	if err != nil {
		return nil, err
	}
	return gen.UpdateDeployCredential200JSONResponse(out), nil
}

// DeleteDeployCredential deletes a credential no target uses; otherwise 409
// listing the targets (the composite foreign key is the backstop).
func (s *Server) DeleteDeployCredential(ctx context.Context, r gen.DeleteDeployCredentialRequestObject) (gen.DeleteDeployCredentialResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeployCredsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.d.Queries.WithTx(tx)
	cur, err := q.LockDeployCredential(ctx, sqlcgen.LockDeployCredentialParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("deploy credential %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	deps, err := q.ListDeployCredentialDependentTargets(ctx, sqlcgen.ListDeployCredentialDependentTargetsParams{CredentialID: &r.Id, OrgID: r.OrgId})
	if err != nil {
		return nil, err
	}
	if len(deps) > 0 {
		names := make([]string, 0, 5)
		for i, d := range deps {
			if i == 5 {
				names = append(names, fmt.Sprintf("and %d more", len(deps)-5))
				break
			}
			names = append(names, d.Name)
		}
		return nil, conflict("This credential is used by %d deploy target(s): %s. Detach it from them first.", len(deps), strings.Join(names, ", "))
	}
	if _, err := q.DeleteDeployCredential(ctx, sqlcgen.DeleteDeployCredentialParams{ID: r.Id, OrgID: r.OrgId}); pgCode(err) == pgForeignKeyViolation {
		return nil, conflict("This credential was just attached to a deploy target; try again.")
	} else if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "deploy_credential.delete", ResourceType: "deploy_credential", ResourceID: r.Id.String(), OrgID: &r.OrgId,
		Details: map[string]any{"name": cur.Name, "kind": cur.Kind}})
	return gen.DeleteDeployCredential204Response{}, nil
}

// RevealDeployCredentialSecret returns one stored secret field in plaintext.
// Global admin only and fail-closed on audit: the event (never carrying the
// value) is recorded before the value is released.
func (s *Server) RevealDeployCredentialSecret(ctx context.Context, r gen.RevealDeployCredentialSecretRequestObject) (gen.RevealDeployCredentialSecretResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionDeployCredsReveal, &r.OrgId); err != nil {
		return nil, err
	}
	if r.Body == nil {
		return nil, badRequest("missing body")
	}
	row, err := s.queries().GetDeployCredential(ctx, sqlcgen.GetDeployCredentialParams{ID: r.Id, OrgID: r.OrgId})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, notFound("deploy credential %s", r.Id)
	}
	if err != nil {
		return nil, err
	}
	field := r.Body.Field
	if !slices.Contains(targets.SecretFields(row.Kind), field) {
		return nil, unprocessable("field", "not a secret field")
	}
	secrets, err := s.openCredentialSecrets(ctx, row.SecretCfg)
	if err != nil {
		return nil, err
	}
	value, ok := secrets[field]
	if !ok {
		return nil, notFound("this field has no stored value")
	}
	if err := s.d.Auditor.Record(ctx, audit.Event{Action: "deploy_credential.secret_revealed", ResourceType: "deploy_credential",
		ResourceID: row.ID.String(), OrgID: &r.OrgId,
		Details: map[string]any{"field": field, "credentialName": row.Name, "kind": row.Kind}}); err != nil {
		return nil, fmt.Errorf("audit secret reveal: %w", err)
	}
	return gen.RevealDeployCredentialSecret200JSONResponse{
		Body:    gen.DeployCredentialRevealResult{Field: field, Value: value},
		Headers: gen.RevealDeployCredentialSecret200ResponseHeaders{CacheControl: "no-store", Pragma: "no-cache"},
	}, nil
}
