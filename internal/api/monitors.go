package api

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/monitor"
	"github.com/metril/certforge/internal/notify"
)

// monitorOut maps a monitor.Monitor to its API shape.
func monitorOut(m monitor.Monitor) gen.Monitor {
	nextCheckAt := m.NextCheckAt
	return gen.Monitor{
		Id: m.ID, OrgId: m.OrgID, Name: m.Name, Host: m.Host, Port: m.Port, Sni: m.SNI,
		IntervalSeconds: m.IntervalSeconds, ExpectedCertificateId: m.ExpectedCertID, ExpectedCertificateName: m.ExpectedCertificateName,
		Enabled: m.Enabled, State: gen.MonitorState(m.State), LastCheckedAt: m.LastCheckedAt, NextCheckAt: &nextCheckAt,
		LastFingerprint: strOrNil(m.LastFingerprint), LastNotAfter: m.LastNotAfter, LastIssuer: strOrNil(m.LastIssuer),
		LastError: strOrNil(m.LastError), CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
	}
}

func strOrNil(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// toMonitorInput converts a MonitorInput request body, applying its own
// defaults (Shared contract: MonitorInput schema).
func toMonitorInput(body *gen.MonitorInput) (monitor.Input, error) {
	if body == nil {
		return monitor.Input{}, badRequest("missing body")
	}
	port := 443
	if body.Port != nil {
		port = *body.Port
	}
	interval := 3600
	if body.IntervalSeconds != nil {
		interval = *body.IntervalSeconds
	}
	enabled := true
	if body.Enabled != nil {
		enabled = *body.Enabled
	}
	return monitor.Input{Name: body.Name, Host: body.Host, Port: port, SNI: body.Sni,
		IntervalSeconds: interval, ExpectedCertID: body.ExpectedCertificateId, Enabled: enabled}, nil
}

// mapMonitorErr turns a monitor domain error into a problem response.
func mapMonitorErr(err error, id interface{ String() string }) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, monitor.ErrNotFound):
		return notFound("monitor %s", id)
	default:
		var ve *monitor.ValidationError
		if errors.As(err, &ve) {
			return unprocessable(ve.Field, ve.Msg)
		}
	}
	return err
}

// monitorAllowLoopback reads the live "notifications" section's
// allowLoopbackUrls (Deviations R5: monitor hosts share the notifier SSRF
// policy), never cached.
func (s *Server) monitorAllowLoopback(ctx context.Context) (bool, error) {
	set, err := notify.Current(ctx, s.d.Settings)
	if err != nil {
		return false, err
	}
	return set.AllowLoopbackURLs, nil
}

// checkExpectedCert validates a submitted expectedCertificateId belongs to
// orgId (Shared contract: "a certificate in another org is 422"); id nil
// is always fine (the mismatch check is then skipped entirely).
func (s *Server) checkExpectedCert(ctx context.Context, orgID uuid.UUID, in monitor.Input) error {
	if in.ExpectedCertID == nil {
		return nil
	}
	if _, err := s.d.Monitors.Store.CertificateName(ctx, orgID, *in.ExpectedCertID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return unprocessable("expectedCertificateId", "must be a certificate in this org")
		}
		return err
	}
	return nil
}

// ListMonitors returns an org's external monitors.
func (s *Server) ListMonitors(ctx context.Context, r gen.ListMonitorsRequestObject) (gen.ListMonitorsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAlertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	rows, err := s.d.Monitors.Store.List(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	out := make(gen.ListMonitors200JSONResponse, 0, len(rows))
	for _, m := range rows {
		out = append(out, monitorOut(m))
	}
	return out, nil
}

// GetMonitor returns one monitor of the org.
func (s *Server) GetMonitor(ctx context.Context, r gen.GetMonitorRequestObject) (gen.GetMonitorResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAlertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	m, err := s.d.Monitors.Store.Get(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapMonitorErr(err, r.Id)
	}
	return gen.GetMonitor200JSONResponse(monitorOut(m)), nil
}

// monitorAuditDetails is a monitor row's create/update/delete/check audit
// shape (Shared contract, Audit row: "monitor.create/update/delete/check
// {monitorId, host, port}").
func monitorAuditDetails(m monitor.Monitor) map[string]any {
	return map[string]any{"monitorId": m.ID, "host": m.Host, "port": m.Port}
}

// CreateMonitor adds an external monitor.
func (s *Server) CreateMonitor(ctx context.Context, r gen.CreateMonitorRequestObject) (gen.CreateMonitorResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAlertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	in, err := toMonitorInput(r.Body)
	if err != nil {
		return nil, err
	}
	allowLoopback, err := s.monitorAllowLoopback(ctx)
	if err != nil {
		return nil, err
	}
	in, err = monitor.ValidateInput(in, allowLoopback)
	if err != nil {
		return nil, mapMonitorErr(err, r.OrgId)
	}
	if err := s.checkExpectedCert(ctx, r.OrgId, in); err != nil {
		return nil, err
	}
	count, err := s.d.Monitors.Store.Count(ctx, r.OrgId)
	if err != nil {
		return nil, err
	}
	if count >= monitor.MaxPerOrg {
		return nil, unprocessable("name", "at most 500 monitors per org")
	}
	m, err := s.d.Monitors.Store.Create(ctx, r.OrgId, in)
	switch pgCode(err) {
	case pgUniqueViolation:
		return nil, conflict("A monitor named %q exists in this org.", in.Name)
	case pgForeignKeyViolation:
		return nil, notFound("org %s", r.OrgId)
	}
	if err != nil {
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "monitor.create", ResourceType: "monitor", ResourceID: m.ID.String(), OrgID: &m.OrgID,
		Details: monitorAuditDetails(m)})
	return gen.CreateMonitor201JSONResponse(monitorOut(m)), nil
}

// UpdateMonitor replaces a monitor's fields; changing host, port, sni or
// expectedCertificateId resets state to unknown and nextCheckAt to now.
func (s *Server) UpdateMonitor(ctx context.Context, r gen.UpdateMonitorRequestObject) (gen.UpdateMonitorResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAlertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	in, err := toMonitorInput(r.Body)
	if err != nil {
		return nil, err
	}
	allowLoopback, err := s.monitorAllowLoopback(ctx)
	if err != nil {
		return nil, err
	}
	in, err = monitor.ValidateInput(in, allowLoopback)
	if err != nil {
		return nil, mapMonitorErr(err, r.OrgId)
	}
	if err := s.checkExpectedCert(ctx, r.OrgId, in); err != nil {
		return nil, err
	}
	cur, err := s.d.Monitors.Store.Get(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapMonitorErr(err, r.Id)
	}
	resetState := monitor.ResetsState(cur, in)
	m, err := s.d.Monitors.Store.Update(ctx, r.OrgId, r.Id, in, resetState)
	if pgCode(err) == pgUniqueViolation {
		return nil, conflict("A monitor named %q exists in this org.", in.Name)
	}
	if err != nil {
		return nil, mapMonitorErr(err, r.Id)
	}
	s.audit(ctx, audit.Event{Action: "monitor.update", ResourceType: "monitor", ResourceID: m.ID.String(), OrgID: &m.OrgID,
		Details: monitorAuditDetails(m)})
	return gen.UpdateMonitor200JSONResponse(monitorOut(m)), nil
}

// DeleteMonitor removes a monitor.
func (s *Server) DeleteMonitor(ctx context.Context, r gen.DeleteMonitorRequestObject) (gen.DeleteMonitorResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAlertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	cur, err := s.d.Monitors.Store.Get(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapMonitorErr(err, r.Id)
	}
	if err := s.d.Monitors.Store.Delete(ctx, r.OrgId, r.Id); err != nil {
		return nil, mapMonitorErr(err, r.Id)
	}
	s.audit(ctx, audit.Event{Action: "monitor.delete", ResourceType: "monitor", ResourceID: r.Id.String(), OrgID: &r.OrgId,
		Details: monitorAuditDetails(cur)})
	return gen.DeleteMonitor204Response{}, nil
}

// CheckMonitor runs one check inline, bounded to monitor.InlineTimeout, and
// returns the updated monitor.
func (s *Server) CheckMonitor(ctx context.Context, r gen.CheckMonitorRequestObject) (gen.CheckMonitorResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionAlertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if _, err := s.d.Monitors.Store.Get(ctx, r.OrgId, r.Id); err != nil {
		return nil, mapMonitorErr(err, r.Id)
	}
	checkCtx, cancel := context.WithTimeout(ctx, monitor.InlineTimeout)
	defer cancel()
	m, err := s.d.Monitors.Check(checkCtx, r.Id)
	if err != nil {
		return nil, mapMonitorErr(err, r.Id)
	}
	s.audit(ctx, audit.Event{Action: "monitor.check", ResourceType: "monitor", ResourceID: m.ID.String(), OrgID: &m.OrgID,
		Details: monitorAuditDetails(m)})
	return gen.CheckMonitor200JSONResponse(monitorOut(m)), nil
}
