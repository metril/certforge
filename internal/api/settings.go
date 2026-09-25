package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/settings"
)

// GetSettingsSection returns a section's schema and value.
func (s *Server) GetSettingsSection(ctx context.Context, req gen.GetSettingsSectionRequestObject) (gen.GetSettingsSectionResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSettingsRead, nil); err != nil {
		return nil, err
	}
	sec, ok := s.d.Sections.Section(req.Section)
	if !ok {
		return nil, notFound("settings section %q", req.Section)
	}
	out, err := s.sectionResponse(ctx, sec)
	if err != nil {
		return nil, err
	}
	return gen.GetSettingsSection200JSONResponse(out), nil
}

// PutSettingsSection validates and stores a section value.
func (s *Server) PutSettingsSection(ctx context.Context, req gen.PutSettingsSectionRequestObject) (gen.PutSettingsSectionResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSettingsWrite, nil); err != nil {
		return nil, err
	}
	sec, ok := s.d.Sections.Section(req.Section)
	if !ok {
		return nil, notFound("settings section %q", req.Section)
	}
	if req.Body == nil {
		return nil, badRequest("missing body")
	}
	raw, err := json.Marshal(req.Body)
	if err != nil {
		return nil, badRequest("%v", err)
	}
	// Schema validation always runs first, so malformed input (including a
	// malformed caId) is a 422 regardless of which section this is.
	if err := sec.Validate(raw); err != nil {
		return nil, &HTTPError{Status: http.StatusUnprocessableEntity, Title: "Invalid settings", Detail: err.Error()}
	}
	before, _, err := s.d.Settings.GetSection(ctx, sec)
	if err != nil {
		return nil, err
	}
	var secretsChanged []string
	if sec.Name == issuance.SettingsKey {
		secretsChanged, err = s.putGlobalIssuanceDefaults(ctx, sec, raw)
	} else {
		secretsChanged, err = s.putSection(ctx, sec, raw)
	}
	if err != nil {
		return nil, err
	}
	if sec.Name == authn.SettingsSection {
		if s.d.AuthSettings != nil {
			s.d.AuthSettings.Invalidate()
		}
		if s.d.OIDC != nil {
			s.d.OIDC.Forget()
		}
	}
	if sec.Name == agents.SettingsSection && s.d.AgentSettings != nil {
		s.d.AgentSettings.Invalidate()
	}
	after, err := sec.Public(raw)
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "settings.update", ResourceType: "settings", ResourceID: sec.Name,
		Details: map[string]any{"section": sec.Name, "before": before, "after": after, "secretsChanged": secretsChanged}})
	out, err := s.sectionResponse(ctx, sec)
	if err != nil {
		return nil, err
	}
	return gen.PutSettingsSection200JSONResponse(out), nil
}

// putSection stores a section value and its secrets in one transaction and
// returns the secret keys PutSectionTx actually changed.
func (s *Server) putSection(ctx context.Context, sec *settings.Section, raw json.RawMessage) ([]string, error) {
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	changed, err := s.d.Settings.PutSectionTx(ctx, tx, sec, raw)
	if err != nil {
		if errors.Is(err, settings.ErrInvalid) || errors.Is(err, settings.ErrUnchangedWithoutStored) {
			return nil, &HTTPError{Status: http.StatusUnprocessableEntity, Title: "Invalid settings", Detail: err.Error()}
		}
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return changed, nil
}

// putGlobalIssuanceDefaults validates and stores the issuance_defaults
// settings section inside one transaction: ValidateGlobalDefaultsTx takes a
// FOR KEY SHARE lock on any referenced CA or account before checking it
// exists, so a concurrent DeleteCA/DeleteAccount (which takes FOR UPDATE on
// the same row) blocks until this transaction commits or rolls back — the
// two writers can no longer interleave into a dangling reference. The
// section is written through the same transaction via PutSectionTx.
func (s *Server) putGlobalIssuanceDefaults(ctx context.Context, sec *settings.Section, raw json.RawMessage) ([]string, error) {
	var d issuance.Defaults
	if err := json.Unmarshal(raw, &d); err != nil {
		// raw already passed JSON-Schema validation above; the schema's
		// format: uuid is an annotation only (not asserted), so a
		// syntactically malformed caId/accountId still reaches here. It is
		// still invalid input, so 422 like every other validation failure
		// on this section, not 400 (which would suggest the request body
		// itself was unparseable JSON).
		return nil, unprocessable("issuance_defaults", err.Error())
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.d.Issuance.Store.ValidateGlobalDefaultsTx(ctx, tx, d); err != nil {
		return nil, mapErr(err)
	}
	changed, err := s.d.Settings.PutSectionTx(ctx, tx, sec, raw)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return changed, nil
}

func (s *Server) sectionResponse(ctx context.Context, sec *settings.Section) (gen.SettingsSection, error) {
	raw, storedRaw, err := s.d.Settings.GetSection(ctx, sec)
	if err != nil {
		return gen.SettingsSection{}, err
	}
	var schema map[string]interface{}
	if err := json.Unmarshal(sec.Schema, &schema); err != nil {
		return gen.SettingsSection{}, err
	}
	value := gen.SettingsValue{}
	if err := json.Unmarshal(raw, &value); err != nil {
		return gen.SettingsSection{}, err
	}
	// Stored is additive (controller ruling, review fix round 1): nil when
	// the section has never been saved, so a client (the issuance_defaults
	// Global tab) can tell that apart from Value's built-in-filled display.
	var stored *gen.SettingsValue
	if storedRaw != nil {
		v := gen.SettingsValue{}
		if err := json.Unmarshal(storedRaw, &v); err != nil {
			return gen.SettingsSection{}, err
		}
		stored = &v
	}
	storedSecrets, err := s.d.Settings.StoredSecretKeys(ctx, sec)
	if err != nil {
		return gen.SettingsSection{}, err
	}
	return gen.SettingsSection{Section: sec.Name, Schema: schema, Value: value, Stored: stored, StoredSecrets: storedSecrets}, nil
}
