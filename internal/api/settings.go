package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/notify"
	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/vault"
)

// smtpTestMaxTimeoutSeconds bounds testSmtpSettings to the Shared
// contract's "10 s bound" regardless of the saved section's own
// timeoutSeconds (1-60): SendMail has no context-cancellation seam
// (net/smtp predates context.Context), so the bound is enforced the same
// way SendMail enforces any timeout — as the connection's own deadline,
// derived from cfg.TimeoutSeconds — not by racing a context against it.
const smtpTestMaxTimeoutSeconds = 10

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
	if sec.Name == agents.SettingsSection {
		if s.d.AgentSettings != nil {
			s.d.AgentSettings.Invalidate()
		}
		if s.d.Agents != nil {
			if err := s.d.Agents.ReloadListener(ctx); err != nil {
				s.d.Log.Error("agent listener not reloaded after a settings change", "err", err)
			}
		}
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

// TestSmtpSettings sends a fixed test email through the saved "smtp"
// settings section to req.Body.To (Shared contract: testSmtpSettings; host,
// port, username, security and timeout all come from storage — only the
// recipient is taken from the request). 422 "SMTP is not configured" when
// the saved section's host is empty; otherwise always 200, with a failed
// send reported as DeliveryResult{status: failed, error} rather than an
// HTTP error, the same pattern TestVaultSettings uses below. Recorded as
// smtp.test {ok} regardless of outcome.
func (s *Server) TestSmtpSettings(ctx context.Context, req gen.TestSmtpSettingsRequestObject) (gen.TestSmtpSettingsResponseObject, error) { //nolint:revive // method name fixed by the testSmtpSettings operationId
	if _, err := authorize(ctx, authz.ActionSettingsWrite, nil); err != nil {
		return nil, err
	}
	if req.Body == nil {
		return nil, badRequest("missing body")
	}
	cfg, password, err := notify.CurrentSMTP(ctx, s.d.Settings, s.d.Sections)
	if err != nil {
		return nil, err
	}
	if cfg.Host == "" {
		return nil, unprocessable("smtp", "SMTP is not configured")
	}
	// The 10s bound is the connection deadline SendMail derives from
	// TimeoutSeconds (smtpTestMaxTimeoutSeconds's doc comment), not a
	// context timeout.
	if cfg.TimeoutSeconds <= 0 || cfg.TimeoutSeconds > smtpTestMaxTimeoutSeconds {
		cfg.TimeoutSeconds = smtpTestMaxTimeoutSeconds
	}

	to := string(req.Body.To)
	start := time.Now()
	sendErr := notify.SendMail(ctx, cfg, password, []string{to},
		"CertForge test email", "This is a test email from CertForge to confirm your SMTP settings are working.\n")
	duration := time.Since(start)

	status := gen.DeliveryStatusDelivered
	out := gen.DeliveryResult{DurationMs: int(duration.Milliseconds()), Status: status}
	ok := sendErr == nil
	if !ok {
		out.Status = gen.DeliveryStatusFailed
		msg := httpx.Redact(sendErr.Error(), password, cfg.Username)
		out.Error = &msg
	}
	s.audit(ctx, audit.Event{Action: "smtp.test", ResourceType: "settings", ResourceID: notify.SMTPSectionName,
		Details: map[string]any{"ok": ok}})
	return gen.TestSmtpSettings200JSONResponse(out), nil
}

// TestVaultSettings validates req.Body against the "vault" section's schema
// and re-entry rule (the same checks PUT /settings/vault runs), then asks
// Vault.Provider to actually log in and look up its own token with the
// resolved settings. A malformed or re-entry-violating request is 422; once
// the request is well-formed, the response is always 200 — Provider.Test
// itself reports an unreachable Vault or bad credentials as
// VaultTestResult.ok == false, not an error (not audited: settings:write is
// enough, this never changes stored state).
func (s *Server) TestVaultSettings(ctx context.Context, req gen.TestVaultSettingsRequestObject) (gen.TestVaultSettingsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSettingsWrite, nil); err != nil {
		return nil, err
	}
	sec, ok := s.d.Sections.Section(vault.SectionName)
	if !ok {
		return nil, notFound("settings section %q", vault.SectionName)
	}
	if req.Body == nil {
		return nil, badRequest("missing body")
	}
	raw, err := json.Marshal(req.Body)
	if err != nil {
		return nil, badRequest("%v", err)
	}
	if err := sec.Validate(raw); err != nil {
		return nil, &HTTPError{Status: http.StatusUnprocessableEntity, Title: "Invalid settings", Detail: err.Error()}
	}
	_, stored, err := s.d.Settings.GetSection(ctx, sec)
	if err != nil {
		return nil, err
	}
	if err := sec.ValidateUpdate(stored, raw); err != nil {
		return nil, &HTTPError{Status: http.StatusUnprocessableEntity, Title: "Invalid settings", Detail: err.Error()}
	}
	if s.d.Vault == nil {
		return gen.TestVaultSettings200JSONResponse{Ok: false, Error: ptr("vault is not configured on this server")}, nil
	}
	res := s.d.Vault.Test(ctx, raw)
	out := gen.VaultTestResult{Ok: res.OK}
	if res.Error != "" {
		out.Error = &res.Error
	}
	if res.OK {
		out.TokenTtlSeconds = &res.TokenTTLSeconds
		out.Policies = &res.Policies
		out.Version = &res.Version
	}
	return gen.TestVaultSettings200JSONResponse(out), nil
}
