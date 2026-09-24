package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
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
	if err := s.d.Settings.PutSection(ctx, sec, raw); err != nil {
		if errors.Is(err, settings.ErrInvalid) {
			return nil, &HTTPError{Status: http.StatusUnprocessableEntity, Title: "Invalid settings", Detail: err.Error()}
		}
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "settings.update", ResourceType: "settings", ResourceID: sec.Name,
		Details: map[string]any{"section": sec.Name}})
	out, err := s.sectionResponse(ctx, sec)
	if err != nil {
		return nil, err
	}
	return gen.PutSettingsSection200JSONResponse(out), nil
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
