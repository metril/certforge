package metrics

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/settings"
)

// CacheTTL bounds how often Collector re-queries the database per Collect
// call (Shared contract): a scrape more often than this reuses the
// previous snapshot instead of hitting the database again
// (TestCollectorCaches).
const CacheTTL = 15 * time.Second

// agentsOnlineCutoffKey/Default mirror the "agents" settings section's own
// offlineAfterSeconds (internal/agents.SettingsSection/its schema default):
// read directly by key here rather than importing internal/agents, which
// pulls in the whole agents.Service — this package only ever needs the one
// field, the same way it reads "backup.status" and settings.RewrapKey
// below without importing internal/backup or internal/kek.
const (
	agentsOnlineCutoffKey     = "section.agents"
	agentsOnlineCutoffDefault = 180 * time.Second
)

// backupStatusKey mirrors the future internal/backup.StatusKey (Task 12,
// not landed yet: Task 8 depends on Tasks 1 and 3 only). Duplicated here as
// a literal so this package does not depend on internal/backup; Task 12
// must keep StatusKey equal to "backup.status" for this to keep working.
const backupStatusKey = "backup.status"

var (
	certificatesDesc = prometheus.NewDesc("certforge_certificates",
		"Certificates by organization and status.", []string{"org", "status"}, nil)
	certNotAfterDesc = prometheus.NewDesc("certforge_certificate_not_after_seconds",
		"Current version expiry (unix seconds) of each certificate that has one. "+
			"Cardinality scales with the number of certificates; the label is the certificate's id.",
		[]string{"org", "certificate"}, nil)
	dueRenewalDesc = prometheus.NewDesc("certforge_certificates_due_renewal",
		"Managed certificates whose next renewal is now or past due.", []string{"org"}, nil)
	clientsDesc = prometheus.NewDesc("certforge_clients",
		"Agent clients by organization and status.", []string{"org", "status"}, nil)
	deploymentsDesc = prometheus.NewDesc("certforge_deployments",
		"Certificate deployments by organization and status.", []string{"org", "status"}, nil)
	monitorsDesc = prometheus.NewDesc("certforge_monitors",
		"External monitors by organization and state.", []string{"org", "state"}, nil)
	riverJobsDesc = prometheus.NewDesc("certforge_river_jobs",
		"Non-completed river jobs by kind and state.", []string{"kind", "state"}, nil)
	backupLastSuccessDesc = prometheus.NewDesc("certforge_backup_last_success_timestamp_seconds",
		"Unix time of the last successful backup; 0 if none has ever completed.", nil, nil)
	rewrapRemainingDesc = prometheus.NewDesc("certforge_kek_rewrap_remaining",
		"Sealed columns still on a non-active KEK, from the most recent rewrap run.", nil, nil)
	buildInfoDesc = prometheus.NewDesc("certforge_build_info",
		"Always 1; labelled with the running server's version.", []string{"version"}, nil)
)

// Collector gathers the database-backed series in the Shared contract's
// Metrics row: certificates by org/status, each certificate's current
// not_after, due renewals, clients by status, deployments (agent- and
// server-run) by status, monitors by state, non-completed river jobs by
// kind/state, the last successful backup's time and the most recent KEK
// rewrap's remaining count. One query set runs per Collect call and is
// cached for CacheTTL.
type Collector struct {
	q       *sqlcgen.Queries
	pool    *pgxpool.Pool
	store   *settings.Store
	version string
	log     *slog.Logger
	now     func() time.Time

	mu   sync.Mutex
	at   time.Time
	snap snapshot
}

type snapshot struct {
	certs        []sqlcgen.MetricsCertificatesByStatusRow
	notAfter     []sqlcgen.MetricsCertificateNotAfterRow
	dueRenewal   []sqlcgen.MetricsCertificatesDueRenewalRow
	clients      []sqlcgen.MetricsClientsByStatusRow
	deployments  []sqlcgen.MetricsDeploymentsByStatusRow
	monitors     []sqlcgen.MetricsMonitorsByStateRow
	riverJobs    []riverJobRow
	backupLast   float64
	rewrapRemain float64
}

type riverJobRow struct {
	Kind  string
	State string
	Count int64
}

// NewCollector returns a Collector for pool/store, labelling
// certforge_build_info with version. Register it on Registry once at boot
// (cmd/certforge/serve.go); Describe is intentionally empty (an "unchecked"
// collector, prometheus/client_golang's own term for one whose Describe
// sends nothing), since every series here has database-derived label
// values unknown ahead of a Collect call.
func NewCollector(pool *pgxpool.Pool, store *settings.Store, version string, log *slog.Logger) prometheus.Collector {
	if log == nil {
		log = slog.Default()
	}
	return &Collector{q: sqlcgen.New(pool), pool: pool, store: store, version: version, log: log, now: time.Now}
}

// Describe intentionally sends nothing; see NewCollector's doc comment.
func (c *Collector) Describe(chan<- *prometheus.Desc) {}

// Collect emits every series from the cached snapshot (refreshed by
// snapshot below when stale).
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	snap := c.snapshot()
	for _, r := range snap.certs {
		ch <- prometheus.MustNewConstMetric(certificatesDesc, prometheus.GaugeValue, float64(r.Count), r.Org, r.Status)
	}
	for _, r := range snap.notAfter {
		ch <- prometheus.MustNewConstMetric(certNotAfterDesc, prometheus.GaugeValue, float64(r.NotAfter.Unix()), r.Org, r.Certificate.String())
	}
	for _, r := range snap.dueRenewal {
		ch <- prometheus.MustNewConstMetric(dueRenewalDesc, prometheus.GaugeValue, float64(r.Count), r.Org)
	}
	for _, r := range snap.clients {
		ch <- prometheus.MustNewConstMetric(clientsDesc, prometheus.GaugeValue, float64(r.Count), r.Org, r.Status)
	}
	// Two UNION ALL branches (agent- and server-run grants) can each
	// contribute a row for the same (org, status): summed here rather than
	// in SQL, since the two SELECTs group independently (metrics.sql).
	deployTotals := map[[2]string]float64{}
	var deployOrder [][2]string
	for _, r := range snap.deployments {
		key := [2]string{r.Org, r.Status}
		if _, ok := deployTotals[key]; !ok {
			deployOrder = append(deployOrder, key)
		}
		deployTotals[key] += float64(r.Count)
	}
	for _, key := range deployOrder {
		ch <- prometheus.MustNewConstMetric(deploymentsDesc, prometheus.GaugeValue, deployTotals[key], key[0], key[1])
	}
	for _, r := range snap.monitors {
		ch <- prometheus.MustNewConstMetric(monitorsDesc, prometheus.GaugeValue, float64(r.Count), r.Org, r.State)
	}
	for _, r := range snap.riverJobs {
		ch <- prometheus.MustNewConstMetric(riverJobsDesc, prometheus.GaugeValue, float64(r.Count), r.Kind, r.State)
	}
	ch <- prometheus.MustNewConstMetric(backupLastSuccessDesc, prometheus.GaugeValue, snap.backupLast)
	ch <- prometheus.MustNewConstMetric(rewrapRemainingDesc, prometheus.GaugeValue, snap.rewrapRemain)
	ch <- prometheus.MustNewConstMetric(buildInfoDesc, prometheus.GaugeValue, 1, c.version)
}

// snapshot returns the cached query results, refreshing them when older
// than CacheTTL (or never fetched). A refresh error leaves the previous
// snapshot in place (best-effort: Collect has no way to return an error,
// and a scrape reusing stale data beats one returning nothing) and is
// logged; the attempt still counts as a refresh, so scrapes during an
// outage serve the last snapshot for CacheTTL instead of each waiting on
// the query timeout.
func (c *Collector) snapshot() snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.at.IsZero() && c.now().Sub(c.at) < CacheTTL {
		return c.snap
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	snap, err := c.query(ctx)
	if err != nil {
		c.log.Warn("metrics refresh failed; serving the previous snapshot", "err", err)
	} else {
		c.snap = snap
	}
	c.at = c.now()
	return c.snap
}

func (c *Collector) query(ctx context.Context) (snapshot, error) {
	var snap snapshot
	var err error
	if snap.certs, err = c.q.MetricsCertificatesByStatus(ctx); err != nil {
		return snapshot{}, err
	}
	if snap.notAfter, err = c.q.MetricsCertificateNotAfter(ctx); err != nil {
		return snapshot{}, err
	}
	if snap.dueRenewal, err = c.q.MetricsCertificatesDueRenewal(ctx); err != nil {
		return snapshot{}, err
	}
	if snap.clients, err = c.q.MetricsClientsByStatus(ctx, c.onlineCutoff(ctx)); err != nil {
		return snapshot{}, err
	}
	if snap.deployments, err = c.q.MetricsDeploymentsByStatus(ctx); err != nil {
		return snapshot{}, err
	}
	if snap.monitors, err = c.q.MetricsMonitorsByState(ctx); err != nil {
		return snapshot{}, err
	}
	if snap.riverJobs, err = c.riverJobs(ctx); err != nil {
		return snapshot{}, err
	}
	snap.backupLast = c.backupLastSuccess(ctx)
	snap.rewrapRemain = c.rewrapRemaining(ctx)
	return snap, nil
}

// onlineCutoff is the oldest last_seen that still counts as online,
// mirroring agents.Service.OnlineCutoff without importing internal/agents
// (this package's own doc comment on agentsOnlineCutoffKey explains why).
func (c *Collector) onlineCutoff(ctx context.Context) time.Time {
	offline := agentsOnlineCutoffDefault
	if c.store != nil {
		var sec struct {
			OfflineAfterSeconds int `json:"offlineAfterSeconds"`
		}
		if err := c.store.Get(ctx, agentsOnlineCutoffKey, &sec); err == nil && sec.OfflineAfterSeconds > 0 {
			offline = time.Duration(sec.OfflineAfterSeconds) * time.Second
		}
	}
	return c.now().Add(-offline)
}

// riverJobs queries river_job directly: it is river's own table (from
// riverpgxv5's migrations, not internal/db/migrations), so sqlc has no
// schema for it to generate a typed query from.
func (c *Collector) riverJobs(ctx context.Context) ([]riverJobRow, error) {
	rows, err := c.pool.Query(ctx, `SELECT kind, state::text, count(*) FROM river_job WHERE state <> 'completed' GROUP BY kind, state`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []riverJobRow
	for rows.Next() {
		var r riverJobRow
		if err := rows.Scan(&r.Kind, &r.State, &r.Count); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// backupLastSuccess reads "backup.status" (backupStatusKey), 0 if the key
// has never been written (Task 12 has not landed, or no backup has ever
// succeeded) or the value fails to decode.
func (c *Collector) backupLastSuccess(ctx context.Context) float64 {
	if c.store == nil {
		return 0
	}
	var st struct {
		LastSuccessAt *time.Time `json:"lastSuccessAt"`
	}
	if err := c.store.Get(ctx, backupStatusKey, &st); err != nil || st.LastSuccessAt == nil {
		return 0
	}
	return float64(st.LastSuccessAt.Unix())
}

// rewrapRemaining reads settings.RewrapKey (kek.RewrapStatus's own
// persisted shape), 0 if a rewrap has never run or the value fails to
// decode.
func (c *Collector) rewrapRemaining(ctx context.Context) float64 {
	if c.store == nil {
		return 0
	}
	var st struct {
		Remaining int64 `json:"remaining"`
	}
	if err := c.store.Get(ctx, settings.RewrapKey, &st); err != nil {
		return 0
	}
	return float64(st.Remaining)
}
