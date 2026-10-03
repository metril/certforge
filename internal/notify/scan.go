package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/riverqueue/river"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

// EventRetention is how long a notification_events row survives the
// hourly prune (task-7 brief; Deviations R2: the prune runs here, not in
// issuance.EnqueueDue, since issuance must not import notify).
const EventRetention = 90 * 24 * time.Hour

// scanLimit bounds each scan query's own result set per run (task-7
// brief: "limit 1000 per kind per run").
const scanLimit = 1000

// agentSince bounds ScanAgentCertExpiringClients (final review fix wave,
// finding 1): agent.cert_expiring is emitted up to AgentCertExpiryWindow
// before the certificate's own not_after, so its dedupe row is pruned at
// roughly not_after + (EventRetention - AgentCertExpiryWindow), not
// not_after + EventRetention — using the shared `since` (now -
// EventRetention) here left a gap where the dedupe row was already gone
// but the scan's own bound still matched, re-emitting the same condition.
func agentSince(now time.Time) time.Time {
	return now.Add(-(EventRetention - AgentCertExpiryWindow))
}

// ScanArgs is the hourly job driving every event source Sources owns
// beyond OnVersion/OnFailure: cert.expiring/expired, deploy.failed/drift,
// client.offline, agent.cert_expiring, and the 90-day event prune.
// External monitors (internal/monitor) and backups (internal/backup) have
// their own periodic jobs.
type ScanArgs struct{}

// Kind implements river.JobArgs.
func (ScanArgs) Kind() string { return "certforge_notify_scan" }

// ScanWorker runs ScanArgs.
type ScanWorker struct {
	river.WorkerDefaults[ScanArgs]
	S *Sources
}

// scanTimeout bounds one ScanWorker run: several sequential scans that may
// each emit many events (each a DB write plus channel fan-out), past
// river's 1-minute worker default.
const scanTimeout = 15 * time.Minute

// Timeout implements river.Worker (see scanTimeout).
func (w *ScanWorker) Timeout(*river.Job[ScanArgs]) time.Duration { return scanTimeout }

// Work implements river.Worker.
func (w *ScanWorker) Work(ctx context.Context, _ *river.Job[ScanArgs]) error {
	return w.S.Scan(ctx)
}

// RegisterRiver is an issuance.RiverExtra: ScanWorker plus the hourly job,
// RunOnStart so a freshly started server catches up immediately instead of
// waiting up to an hour for its first pass.
func (s *Sources) RegisterRiver(workers *river.Workers) []*river.PeriodicJob {
	river.AddWorker(workers, &ScanWorker{S: s})
	return []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(time.Hour),
		func() (river.JobArgs, *river.InsertOpts) { return ScanArgs{}, nil },
		&river.PeriodicJobOpts{RunOnStart: true})}
}

// Scan runs every scan source once and prunes events older than
// EventRetention. A single source's own query failing is logged and does
// not stop the others (a transient failure on, say, the deploy scan must
// not also block the prune or the expiry scan); a failure loading the
// settings this run needs (notifications/agents sections) fails the whole
// job instead, since every source below depends on one or the other.
func (s *Sources) Scan(ctx context.Context) error {
	now := s.now()
	// since bounds every scan below that has no other natural lower bound
	// (batch-3 review finding 2): PruneOldNotificationEvents deletes a
	// condition's dedupe row after EventRetention, so a scan with no lower
	// time bound of its own would see NOT EXISTS pass again for a condition
	// that is still ongoing but older than the prune window, and re-emit it.
	// scanExpiring needs no such bound (its not_after > now() is itself
	// always in the future, never eligible for pruning).
	since := now.Add(-EventRetention)
	set, err := Current(ctx, s.Settings)
	if err != nil {
		return fmt.Errorf("notify: scan settings: %w", err)
	}
	offline, err := s.offlineCutoff(ctx, now)
	if err != nil {
		return fmt.Errorf("notify: scan agents settings: %w", err)
	}

	if err := s.scanExpiring(ctx, now, set.ExpiryWarningDays); err != nil {
		s.log().Error("notify: cert.expiring scan failed", "err", err)
	}
	if err := s.scanExpired(ctx, since); err != nil {
		s.log().Error("notify: cert.expired scan failed", "err", err)
	}
	if err := s.scanDeployments(ctx, since); err != nil {
		s.log().Error("notify: deploy scan failed", "err", err)
	}
	if err := s.scanOffline(ctx, offline, since); err != nil {
		s.log().Error("notify: client.offline scan failed", "err", err)
	}
	if err := s.scanAgentCertExpiring(ctx, now, agentSince(now)); err != nil {
		s.log().Error("notify: agent.cert_expiring scan failed", "err", err)
	}
	if _, err := s.Q.PruneOldNotificationEvents(ctx, now.Add(-EventRetention)); err != nil {
		s.log().Error("notify: event prune failed", "err", err)
	}
	return nil
}

func (s *Sources) scanExpiring(ctx context.Context, now time.Time, warningDays int) error {
	cutoff := now.Add(time.Duration(warningDays) * 24 * time.Hour)
	rows, err := s.Q.ScanExpiringCertificateVersions(ctx, sqlcgen.ScanExpiringCertificateVersionsParams{
		Cutoff: cutoff, PageLimit: scanLimit})
	if err != nil {
		return err
	}
	for _, r := range rows {
		ev := Event{
			Kind:      "cert.expiring",
			OrgID:     &r.OrgID,
			Resource:  Resource{ID: r.CertID.String(), Name: r.CommonName},
			Summary:   fmt.Sprintf("%s expires %s", r.CommonName, r.NotAfter.UTC().Format("2006-01-02")),
			Details:   map[string]any{"commonName": r.CommonName, "notAfter": r.NotAfter},
			DedupeKey: "cert.expiring:" + r.VersionID.String(),
		}
		if _, err := s.Emitter.Emit(ctx, nil, ev); err != nil {
			s.log().Error("notify: cert.expiring not emitted", "cert", r.CertID, "err", err)
		}
	}
	return nil
}

func (s *Sources) scanExpired(ctx context.Context, since time.Time) error {
	rows, err := s.Q.ScanExpiredCertificateVersions(ctx, sqlcgen.ScanExpiredCertificateVersionsParams{
		Since: since, PageLimit: scanLimit})
	if err != nil {
		return err
	}
	for _, r := range rows {
		ev := Event{
			Kind:      "cert.expired",
			OrgID:     &r.OrgID,
			Resource:  Resource{ID: r.CertID.String(), Name: r.CommonName},
			Summary:   fmt.Sprintf("%s expired %s", r.CommonName, r.NotAfter.UTC().Format("2006-01-02")),
			Details:   map[string]any{"commonName": r.CommonName, "notAfter": r.NotAfter},
			DedupeKey: "cert.expired:" + r.VersionID.String(),
		}
		if _, err := s.Emitter.Emit(ctx, nil, ev); err != nil {
			s.log().Error("notify: cert.expired not emitted", "cert", r.CertID, "err", err)
		}
	}
	return nil
}

// scanDeployments covers both deploy.failed/deploy.drift for agent-run
// grants (client_cert_grants/deployments) and deploy.failed for
// server-run grants (client_cert_grants/server_deployments, which has no
// drift state of its own — task-7 brief).
func (s *Sources) scanDeployments(ctx context.Context, since time.Time) error {
	rows, err := s.Q.ScanFailedOrDriftedDeployments(ctx, sqlcgen.ScanFailedOrDriftedDeploymentsParams{
		Since: since, PageLimit: scanLimit})
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.VersionID == nil {
			continue // defensive: the query already filters this out
		}
		kind := "deploy." + r.State // "deploy.failed" or "deploy.drift"
		details := map[string]any{"target": r.TargetName}
		if r.State == "failed" {
			details["lastError"] = redactURLs(r.Error)
		}
		ev := Event{
			Kind:      kind,
			OrgID:     &r.OrgID,
			Resource:  Resource{ID: r.GrantID.String(), Name: r.CertificateName + " → " + r.TargetName},
			Summary:   fmt.Sprintf("Deployment of %s to %s %s", r.CertificateName, r.TargetName, r.State),
			Details:   details,
			DedupeKey: fmt.Sprintf("%s:%s:%s", kind, r.GrantID, r.VersionID),
		}
		if _, err := s.Emitter.Emit(ctx, nil, ev); err != nil {
			s.log().Error("notify: deploy event not emitted", "grant", r.GrantID, "err", err)
		}
	}

	srows, err := s.Q.ScanFailedServerDeployments(ctx, sqlcgen.ScanFailedServerDeploymentsParams{
		Since: since, PageLimit: scanLimit})
	if err != nil {
		return err
	}
	for _, r := range srows {
		if r.VersionID == nil {
			continue // defensive: the query already filters this out
		}
		// A server-run target's last_error can be a raw Vault transport
		// error (e.g. a *url.Error whose Error() embeds the request URL;
		// vault.Redact only strips the token/secretId, not the address
		// itself) — redactURLs strips any embedded URL or dial address
		// before it ever reaches an event's details (R10, batch-3 review
		// finding 3).
		ev := Event{
			Kind:      "deploy.failed",
			OrgID:     &r.OrgID,
			Resource:  Resource{ID: r.GrantID.String(), Name: r.CertificateName + " → " + r.TargetName},
			Summary:   fmt.Sprintf("Deployment of %s to %s failed", r.CertificateName, r.TargetName),
			Details:   map[string]any{"target": r.TargetName, "lastError": redactURLs(r.LastError)},
			DedupeKey: fmt.Sprintf("deploy.failed:%s:%s", r.GrantID, r.VersionID),
		}
		if _, err := s.Emitter.Emit(ctx, nil, ev); err != nil {
			s.log().Error("notify: server deploy event not emitted", "grant", r.GrantID, "err", err)
		}
	}
	return nil
}

func (s *Sources) scanOffline(ctx context.Context, cutoff, since time.Time) error {
	rows, err := s.Q.ScanOfflineClients(ctx, sqlcgen.ScanOfflineClientsParams{Cutoff: cutoff, Since: since, PageLimit: scanLimit})
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.LastSeen == nil {
			continue // defensive: the query already filters this out
		}
		ev := Event{
			Kind:      "client.offline",
			OrgID:     &r.OrgID,
			Resource:  Resource{ID: r.ClientID.String(), Name: r.ClientName},
			Summary:   fmt.Sprintf("%s has not reported in", r.ClientName),
			Details:   map[string]any{"lastSeen": *r.LastSeen},
			DedupeKey: fmt.Sprintf("client.offline:%s:%d", r.ClientID, r.LastSeen.Unix()),
		}
		if _, err := s.Emitter.Emit(ctx, nil, ev); err != nil {
			s.log().Error("notify: client.offline not emitted", "client", r.ClientID, "err", err)
		}
	}
	return nil
}

func (s *Sources) scanAgentCertExpiring(ctx context.Context, now, since time.Time) error {
	cutoff := now.Add(AgentCertExpiryWindow)
	rows, err := s.Q.ScanAgentCertExpiringClients(ctx, sqlcgen.ScanAgentCertExpiringClientsParams{
		Cutoff: cutoff, Since: since, PageLimit: scanLimit})
	if err != nil {
		return err
	}
	for _, r := range rows {
		if r.AgentCertNotAfter == nil {
			continue // defensive: the query already filters this out
		}
		ev := Event{
			Kind:      "agent.cert_expiring",
			OrgID:     &r.OrgID,
			Resource:  Resource{ID: r.ClientID.String(), Name: r.ClientName},
			Summary:   fmt.Sprintf("%s's agent certificate expires %s", r.ClientName, r.AgentCertNotAfter.UTC().Format("2006-01-02")),
			Details:   map[string]any{"notAfter": *r.AgentCertNotAfter},
			DedupeKey: fmt.Sprintf("agent.cert_expiring:%s:%s", r.ClientID, r.AgentCertSerial),
		}
		if _, err := s.Emitter.Emit(ctx, nil, ev); err != nil {
			s.log().Error("notify: agent.cert_expiring not emitted", "client", r.ClientID, "err", err)
		}
	}
	return nil
}
