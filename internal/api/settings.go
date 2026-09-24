package api

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
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
	if sec.Name == issuance.SettingsKey {
		if err := s.putGlobalIssuanceDefaults(ctx, sec, raw); err != nil {
			return nil, err
		}
	} else {
		// Settings.Set takes v any and re-marshals it; the explicit
		// json.RawMessage conversion matters here — passing raw's plain
		// []byte would base64-encode it as a JSON string instead of storing
		// the object, since []byte (unlike json.RawMessage) doesn't
		// implement json.Marshaler.
		if err := s.d.Settings.Set(ctx, sec.Key(), json.RawMessage(raw)); err != nil {
			return nil, err
		}
	}
	s.audit(ctx, audit.Event{Action: "settings.update", ResourceType: "settings", ResourceID: sec.Name,
		Details: map[string]any{"section": sec.Name}})
	out, err := s.sectionResponse(ctx, sec)
	if err != nil {
		return nil, err
	}
	return gen.PutSettingsSection200JSONResponse(out), nil
}

// putGlobalIssuanceDefaults validates and stores the issuance_defaults
// settings section inside one transaction: ValidateGlobalDefaultsTx takes a
// FOR KEY SHARE lock on any referenced CA or account before checking it
// exists, so a concurrent DeleteCA/DeleteAccount (which takes FOR UPDATE on
// the same row) blocks until this transaction commits or rolls back — the
// two writers can no longer interleave into a dangling reference. The
// section is written through the same transaction via PutSectionTx.
func (s *Server) putGlobalIssuanceDefaults(ctx context.Context, sec *settings.Section, raw json.RawMessage) error {
	var d issuance.Defaults
	if err := json.Unmarshal(raw, &d); err != nil {
		// raw already passed JSON-Schema validation above; the schema's
		// format: uuid is an annotation only (not asserted), so a
		// syntactically malformed caId/accountId still reaches here. It is
		// still invalid input, so 422 like every other validation failure
		// on this section, not 400 (which would suggest the request body
		// itself was unparseable JSON).
		return unprocessable("issuance_defaults", err.Error())
	}
	tx, err := s.d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := s.d.Issuance.Store.ValidateGlobalDefaultsTx(ctx, tx, d); err != nil {
		return mapErr(err)
	}
	if err := s.d.Settings.PutSectionTx(ctx, tx, sec, raw); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *Server) sectionResponse(ctx context.Context, sec *settings.Section) (gen.SettingsSection, error) {
	raw, err := s.d.Settings.GetSection(ctx, sec)
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
	return gen.SettingsSection{Section: sec.Name, Schema: schema, Value: value}, nil
}
