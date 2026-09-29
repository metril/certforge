package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/settings"
)

// AgentCertExpiryWindow is how far ahead agent.cert_expiring looks (task-7
// brief): fixed, unlike cert.expiring's operator-configurable
// expiryWarningDays, since an agent certificate is CertForge's own and
// renews itself automatically (agentca.Listener/the agent's own renewal) —
// this only ever fires when that self-renewal has somehow stopped working.
const AgentCertExpiryWindow = 14 * 24 * time.Hour

// Sources is every R2 event source except external monitors (internal/monitor's
// own Service, Task 9) and backups (internal/backup's own Service, Task 12):
// cert.issued and cert.renewal_failed synchronously, off the issuance
// worker's own listener hooks, and the rest via the hourly Scan.
type Sources struct {
	Q        *sqlcgen.Queries
	Emitter  *Emitter
	Settings *settings.Store
	// Now overrides time.Now (tests only).
	Now func() time.Time
	Log *slog.Logger
}

func (s *Sources) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func (s *Sources) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// compile-time interface checks (issuance.IssueWorker.Listeners/OnFailure,
// cmd/certforge/serve.go — Task 14 wires the values, this package only
// exposes them).
var (
	_ issuance.VersionListener = (*Sources)(nil)
	_ issuance.FailureListener = (*Sources)(nil)
)

// ---- issuance.VersionListener ----

// OnVersion emits cert.issued. It hangs off issueWorker.Listeners only
// (task-7 brief): an uploaded or imported version never reaches this,
// since certstore's own upload/import path never calls a VersionListener.
// Errors are logged, never returned (the same contract every
// VersionListener already has — OnVersion cannot fail the issuance that
// triggered it).
func (s *Sources) OnVersion(ctx context.Context, certID, versionID uuid.UUID) {
	row, err := s.Q.GetEventCertificateVersion(ctx, versionID)
	if err != nil {
		s.log().Error("notify: cert.issued details unavailable", "cert", certID, "version", versionID, "err", err)
		return
	}
	names := append([]string{row.CommonName}, row.Sans...)
	ev := Event{
		Kind:  "cert.issued",
		OrgID: &row.OrgID,
		Resource: Resource{
			ID:   certID.String(),
			Name: row.CertificateName,
		},
		Summary: fmt.Sprintf("%s issued (serial %s)", row.CommonName, row.Serial),
		Details: map[string]any{
			"serial":   row.Serial,
			"notAfter": row.NotAfter,
			"names":    names,
			"caName":   row.CaName,
		},
		DedupeKey: "cert.issued:" + versionID.String(),
	}
	if _, err := s.Emitter.Emit(ctx, nil, ev); err != nil {
		s.log().Error("notify: cert.issued not emitted", "cert", certID, "version", versionID, "err", err)
	}
}

// ---- issuance.FailureListener ----

// OnFailure emits cert.renewal_failed once failures reaches the live
// notifications.failureThreshold, at most once per UTC calendar day (the
// dedupe key's own trailing :<date>). cause is never read here: f is
// already issuance.ClassifyFailure's classified, URL/host-free view of it
// (task-7 brief: "cause.Error() is never emitted").
func (s *Sources) OnFailure(ctx context.Context, cert issuance.Certificate, failures int, f issuance.FailureInfo) {
	set, err := Current(ctx, s.Settings)
	if err != nil {
		s.log().Error("notify: cert.renewal_failed threshold unavailable", "cert", cert.ID, "err", err)
		return
	}
	if failures < set.FailureThreshold {
		return
	}
	today := s.now().UTC().Format("2006-01-02")
	details := map[string]any{
		"failures": failures,
		"step":     f.Step,
		"class":    f.Class,
	}
	if f.ProblemType != "" {
		details["problemType"] = f.ProblemType
	}
	if f.Status != 0 {
		details["status"] = f.Status
	}
	if cert.NextRenewAt != nil {
		details["nextAttemptAt"] = *cert.NextRenewAt
	}
	ev := Event{
		Kind:  "cert.renewal_failed",
		OrgID: &cert.OrgID,
		Resource: Resource{
			ID:   cert.ID.String(),
			Name: cert.Name,
		},
		Summary:   fmt.Sprintf("Renewal of %s failed (%s, attempt %d)", cert.CommonName, f.Class, failures),
		Details:   details,
		DedupeKey: fmt.Sprintf("cert.renewal_failed:%s:%s", cert.ID, today),
	}
	if _, err := s.Emitter.Emit(ctx, nil, ev); err != nil {
		s.log().Error("notify: cert.renewal_failed not emitted", "cert", cert.ID, "err", err)
	}
}

// offlineCutoff is the oldest last_seen that still counts as online (now
// minus agents' own offlineAfterSeconds): this package must not import
// internal/agents' Service (it never needs a live Hub or its
// SettingsSource cache), only the section's own name/Settings/Resolve, the
// same section agents.Service.OnlineCutoff itself resolves from.
func (s *Sources) offlineCutoff(ctx context.Context, now time.Time) (time.Time, error) {
	var raw json.RawMessage
	err := s.Settings.Get(ctx, settings.SectionKey(agents.SettingsSection), &raw)
	if err != nil && !errors.Is(err, settings.ErrNotFound) {
		return time.Time{}, err
	}
	var as agents.Settings
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &as); err != nil {
			return time.Time{}, err
		}
	}
	resolved := agents.Resolve(as, "")
	return now.Add(-time.Duration(resolved.OfflineAfterSeconds) * time.Second), nil
}
