package deploy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/targets"
)

// maxLastError bounds server_deployments.last_error (Shared contract:
// ServerDeployment.lastError, <= 1000 chars).
const maxLastError = 1000

// DeployArgs is the river job that deploys one server grant's certificate
// material to its target.
type DeployArgs struct {
	GrantID   uuid.UUID `json:"grant_id"`
	VersionID uuid.UUID `json:"version_id"`
	// Seq is server_deployments.deploy_seq at enqueue time: it keeps a
	// re-enqueue of the same version from being dropped as a duplicate of a
	// running (stale) job, and lets that stale job be recognised.
	Seq int64 `json:"seq"`
}

// Kind implements river.JobArgs.
func (DeployArgs) Kind() string { return "certforge_server_deploy" }

// InsertOpts makes the job unique per (grant, version) while queued,
// running or scheduled for retry; a completed or discarded job never blocks
// a later attempt at the same grant and version (Redeploy re-enqueues it).
func (DeployArgs) InsertOpts() river.InsertOpts {
	return river.InsertOpts{
		MaxAttempts: 5,
		UniqueOpts: river.UniqueOpts{
			ByArgs: true,
			ByState: []rivertype.JobState{rivertype.JobStateAvailable, rivertype.JobStatePending,
				rivertype.JobStateRunning, rivertype.JobStateRetryable, rivertype.JobStateScheduled},
		},
	}
}

// Inserter is the subset of *river.Client[pgx.Tx] Dispatcher needs to
// enqueue a deploy job inside an existing transaction; production passes
// the real river client, tests a fake (same pattern as kek.Inserter).
type Inserter interface {
	InsertTx(ctx context.Context, tx pgx.Tx, args river.JobArgs, opts *river.InsertOpts) (*rivertype.JobInsertResult, error)
}

// Events lets fail raise a deploy.failed notification immediately after a
// server-run deploy attempt fails (task-7 brief), without this package
// importing internal/notify directly: internal/notify's own DeployEvents
// implements this by importing internal/deploy the other way around
// (Global Constraints: internal/deploy must never import internal/notify).
// cmd/certforge/serve.go wires the real notify.DeployEvents in; nil (every
// existing test fixture, unless a test sets it) makes fail skip the emit.
type Events interface {
	DeployFailed(ctx context.Context, f DeployFailure) error
}

// DeployFailure is one failed server-run deploy attempt, ready for
// Events.DeployFailed to turn into a notify.Event. LastError is already
// redacted (fail's own targets.Redact pass) — never the raw cause.
type DeployFailure struct {
	OrgID, GrantID, VersionID uuid.UUID
	CertName, TargetName      string
	LastError                 string
}

// Dispatcher is the server-side counterpart to an enrolled agent for
// client-less grants: it hears about every new certificate version
// (issuance.VersionListener), enqueues certforge_server_deploy for each
// live server grant of that certificate, and its DeployWorker renders and
// writes the certificate material to the grant's target.
type Dispatcher struct {
	Pool  *pgxpool.Pool
	Q     *sqlcgen.Queries
	Reg   *targets.Registry
	Certs *certstore.Store
	// Box opens a deploy target's secret_cfg (targetSecrets's own doc
	// comment, internal/api/delivery.go): sealed with the same crypto.Box
	// the target write path uses to seal it.
	Box crypto.Box
	// HTTP builds this deploy's outbound targets.HTTPFactory, reading the
	// org's live "notifications" allowLoopbackUrls setting (cmd/certforge/serve.go) —
	// a func, not a stored value, because Deploy must always see the
	// current setting, never one cached at Dispatcher construction time.
	HTTP func(ctx context.Context) targets.HTTPFactory
	// Events, when set, gets a DeployFailed call from fail after every
	// failed server-run deploy attempt (task-7 brief). nil skips the emit
	// — the hourly notify.Sources.Scan's own ScanFailedServerDeployments
	// still catches it later, as a backstop (Deviations R7).
	Events Events
	River  Inserter
	Log    *slog.Logger

	// afterStaleRead, when set, runs in SweepDeployments right after the
	// stale list is read (test seam for the read-then-enqueue race).
	afterStaleRead func()
}

func (d *Dispatcher) log() *slog.Logger {
	if d.Log != nil {
		return d.Log
	}
	return slog.Default()
}

// OnVersion implements issuance.VersionListener: every live server grant of
// certID gets its server_deployments row reset to pending and a fresh
// certforge_server_deploy job — including a live server grant of a
// *different* certificate whose layout bundles certID as an extra
// certificate (final review finding 5): that grant's own material changes
// too (the extra certificate it renders alongside its own), so it must
// redeploy on certID's own current version, not certID's. Errors are
// logged only (OnVersion cannot fail the issuance that triggered it); one
// grant's failure does not stop the others.
func (d *Dispatcher) OnVersion(ctx context.Context, certID, versionID uuid.UUID) {
	ids, err := d.Q.LiveServerGrantIDsForCert(ctx, certID)
	if err != nil {
		d.log().Error("deploy: server grants not enqueued for a new certificate version", "cert", certID, "version", versionID, "err", err)
		return
	}
	for _, id := range ids {
		if err := d.enqueueTx(ctx, id, &versionID); err != nil {
			d.log().Error("deploy: server grant not enqueued", "grant", id, "cert", certID, "version", versionID, "err", err)
		}
	}
	extras, err := d.Q.LiveServerGrantsForExtraCert(ctx, certID)
	if err != nil {
		d.log().Error("deploy: server grants (as extra certificate) not enqueued for a new certificate version", "cert", certID, "version", versionID, "err", err)
		return
	}
	for _, g := range extras {
		if g.CurrentVersionID == nil {
			continue
		}
		if err := d.enqueueTx(ctx, g.ID, g.CurrentVersionID); err != nil {
			d.log().Error("deploy: server grant (as extra certificate) not enqueued", "grant", g.ID, "extraCert", certID, "err", err)
		}
	}
}

// ResyncCertificateRename implements the issuance.RenameHook shape (only
// ever wired into it combined with agents.Service.ResyncCertificateRename,
// in cmd/certforge/serve.go): final review finding 5, second half. A
// rename does not create a new version, but a vault-kv target's default
// path template embeds the certificate's own name ({name},
// deploy.VaultKVConfig/docs/deploy-targets.md), so a live server grant of
// the renamed certificate must redeploy to write its material at the new
// path. Nothing here needs q (tx-scoped, but this shape's rename commits
// with no server-deploy-specific write of its own) — the returned nudge,
// run after the rename commits exactly like OnVersion normally runs after
// an issuance commits, looks the certificate's current version up fresh
// and re-enqueues through OnVersion itself, which also covers this
// certificate's own extra-cert grants (harmless, idempotent, if any lists
// it as an extra rather than its own).
func (d *Dispatcher) ResyncCertificateRename(ctx context.Context, q *sqlcgen.Queries, certID uuid.UUID) (func(), error) {
	// S4: the new name must not make two grants of one vault-kv target
	// render the same KV path; a conflict fails the rename.
	cert, err := q.GetCertificateByID(ctx, certID)
	if err != nil {
		return nil, err
	}
	grantIDs, err := q.LiveServerGrantIDsForCert(ctx, certID)
	if err != nil {
		return nil, err
	}
	seen := map[uuid.UUID]bool{}
	var tids []uuid.UUID
	for _, gid := range grantIDs {
		views, err := q.ServerGrantViews(ctx, sqlcgen.ServerGrantViewsParams{OrgID: cert.OrgID, GrantID: &gid})
		if err != nil {
			return nil, err
		}
		for _, v := range views {
			if v.DeployTargetID != nil && !seen[*v.DeployTargetID] {
				seen[*v.DeployTargetID] = true
				tids = append(tids, *v.DeployTargetID)
			}
		}
	}
	// Lock order everywhere is certificate, then target (this rename holds
	// the certificate row FOR UPDATE; createServerGrant locks the
	// certificate before the target); targets in id order so two renames
	// touching several targets cannot deadlock. The lock makes the check
	// below see every concurrent rename and grant create.
	sort.Slice(tids, func(i, j int) bool { return bytes.Compare(tids[i][:], tids[j][:]) < 0 })
	for _, tid := range tids {
		t, err := q.DeployTargetForUpdate(ctx, sqlcgen.DeployTargetForUpdateParams{ID: tid, OrgID: cert.OrgID})
		if err != nil {
			return nil, err
		}
		if t.Type != TypeVaultKV {
			continue
		}
		if err := CheckServerGrantPaths(ctx, q, cert.OrgID, tid); err != nil {
			return nil, err
		}
	}
	return func() {
		rows, err := d.Q.CurrentVersionsForCerts(ctx, []uuid.UUID{certID})
		if err != nil {
			d.log().Error("deploy: server grants not re-enqueued after a certificate rename", "cert", certID, "err", err)
			return
		}
		if len(rows) == 0 || rows[0].CurrentVersionID == nil {
			return
		}
		d.OnVersion(ctx, certID, *rows[0].CurrentVersionID)
	}, nil
}

// enqueueTx upserts grantID's server_deployments row pending on versionID
// and enqueues the job, in its own transaction.
func (d *Dispatcher) enqueueTx(ctx context.Context, grantID uuid.UUID, versionID *uuid.UUID) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := d.EnqueueTx(ctx, tx, d.Q.WithTx(tx), grantID, versionID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// EnqueueTx upserts grantID's server_deployments row pending on versionID
// (nil for a certificate with no version yet, C3: nothing to deploy) and,
// when versionID is non-nil, enqueues certforge_server_deploy via tx,
// inside the caller's own transaction and q (which must be tx-scoped).
// CreateServerGrant and the server-grant paths of updateGrant/redeployGrant
// (internal/api/grants.go) call this from their own transactions so the
// grant write and the enqueue commit together.
func (d *Dispatcher) EnqueueTx(ctx context.Context, tx pgx.Tx, q *sqlcgen.Queries, grantID uuid.UUID, versionID *uuid.UUID) error {
	seq, err := q.UpsertServerDeploymentPending(ctx, sqlcgen.UpsertServerDeploymentPendingParams{GrantID: grantID, VersionID: versionID})
	if err != nil {
		return err
	}
	if versionID == nil {
		return nil
	}
	_, err = d.River.InsertTx(ctx, tx, DeployArgs{GrantID: grantID, VersionID: *versionID, Seq: seq}, nil)
	return err
}

// DeployWorker runs DeployArgs.
type DeployWorker struct {
	river.WorkerDefaults[DeployArgs]
	D *Dispatcher
}

// deployTimeout bounds one DeployWorker run: decrypting target secrets,
// rendering material and one write to a remote target, past river's
// 1-minute worker default.
const deployTimeout = 10 * time.Minute

// Timeout implements river.Worker (see deployTimeout).
func (w *DeployWorker) Timeout(*river.Job[DeployArgs]) time.Duration { return deployTimeout }

// Work implements river.Worker.
func (w *DeployWorker) Work(ctx context.Context, job *river.Job[DeployArgs]) error {
	return w.D.deploy(ctx, job.Args.GrantID, job.Args.VersionID, &job.Args.Seq)
}

// SweepDeployments re-enqueues every live server grant that is missing a
// deployment, lags its certificate's current version, or has sat
// pending/failed for over 15 minutes (a river job dropped after
// MaxAttempts, lost to a crash before the enqueue, or truncated by a backup
// restore). Bounded per run by the query; the next run takes the rest.
func (d *Dispatcher) SweepDeployments(ctx context.Context) error {
	rows, err := d.Q.StaleServerDeployments(ctx)
	if err != nil {
		return err
	}
	if d.afterStaleRead != nil {
		d.afterStaleRead()
	}
	if len(rows) > 0 {
		d.log().Info("deploy: re-enqueueing stale server deployments", "grants", len(rows))
	}
	var first error
	for _, r := range rows {
		if err := d.sweepOne(ctx, r.ID); err != nil {
			d.log().Error("deploy: stale server grant not enqueued", "grant", r.ID, "err", err)
			if first == nil {
				first = err
			}
		}
	}
	return first
}

// sweepOne re-arms one stale grant inside a single transaction that first
// locks the certificate row and re-reads current_version_id: the stale list
// was read earlier, so a version that landed since must be deployed (not the
// old one the list saw), and a grant OnVersion has already put on it is left
// alone.
func (d *Dispatcher) sweepOne(ctx context.Context, grantID uuid.UUID) error {
	tx, err := d.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := d.Q.WithTx(tx)
	st, err := q.LockServerGrantForSweep(ctx, grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if !st.Stale {
		return nil
	}
	if err := d.EnqueueTx(ctx, tx, q, grantID, st.CurrentVersionID); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// SweepArgs is the periodic river job that runs SweepDeployments.
type SweepArgs struct{}

// Kind is the river job kind.
func (SweepArgs) Kind() string { return "certforge_server_deployment_sweep" }

// SweepWorker runs SweepArgs.
type SweepWorker struct {
	river.WorkerDefaults[SweepArgs]
	D *Dispatcher
}

// Work runs one sweep.
func (w *SweepWorker) Work(ctx context.Context, _ *river.Job[SweepArgs]) error {
	return w.D.SweepDeployments(ctx)
}

// RegisterRiver is an issuance.RiverExtra: DeployWorker, plus SweepWorker
// and its periodic job (every 15 minutes).
func (d *Dispatcher) RegisterRiver(workers *river.Workers) []*river.PeriodicJob {
	river.AddWorker(workers, &DeployWorker{D: d})
	river.AddWorker(workers, &SweepWorker{D: d})
	return []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(15*time.Minute),
		func() (river.JobArgs, *river.InsertOpts) { return SweepArgs{}, nil }, nil)}
}

// Deploy renders grantID's certificate material at versionID and writes it
// to its target. A grant already removed (row gone, or hard-deleted) is
// simply done: no error, nothing to retry. versionID must still be the
// grant's own pending version (server_deployments.version_id) — a job for
// an older version that finishes after a newer one has already taken over
// (a fresh OnVersion, or a redeploy, moved the grant on) is stale and does
// nothing at all, successfully: overwriting Vault with an old certificate
// and marking it "deployed" would be worse than leaving the newer job to
// run (batch-5 review). Any other failure records a redacted, truncated
// last_error on server_deployments and is returned so river retries with
// backoff.
// DeployWorker.Work calls this for certforge_server_deploy; it is also
// exported for a test to run one deploy attempt directly, without a live
// river client.
func (d *Dispatcher) Deploy(ctx context.Context, grantID, versionID uuid.UUID) error {
	return d.deploy(ctx, grantID, versionID, nil)
}

// deploy is Deploy with the job's deploy_seq: wantSeq non-nil must equal the
// row's current deploy_seq, else the job is stale (the row was re-armed
// since it was enqueued) and does nothing; nil adopts the row's own.
func (d *Dispatcher) deploy(ctx context.Context, grantID, versionID uuid.UUID, wantSeq *int64) error {
	row, err := d.Q.ServerDeployGrant(ctx, grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if row.PendingVersionID == nil || *row.PendingVersionID != versionID || row.PendingDeploySeq == nil {
		return nil
	}
	seq := *row.PendingDeploySeq
	if wantSeq != nil && *wantSeq != seq {
		return nil
	}
	target, ok := d.Reg.Get(row.TargetType)
	if !ok {
		return d.fail(ctx, row, versionID, seq, nil, fmt.Errorf("deploy: unknown target type %q", row.TargetType))
	}
	// A client-less grant may only ever be created on a target whose
	// resolved side is server (API's validTarget/CreateServerGrant path);
	// this is defense in depth against the registry and the grant's own
	// target drifting apart (a type re-registered as agent-only), not the
	// only guard.
	if target.RunsOn() == targets.Agent {
		return d.fail(ctx, row, versionID, seq, nil, fmt.Errorf("deploy: %s runs on an agent, not the server", row.TargetName))
	}

	secrets, err := d.openTargetSecrets(ctx, row.TargetSecretCfg)
	if err != nil {
		return d.fail(ctx, row, versionID, seq, nil, err)
	}

	needsKey, err := d.Reg.NeedsKey(row.TargetType, row.TargetConfig)
	if err != nil {
		return d.fail(ctx, row, versionID, seq, secrets, err)
	}

	m, err := d.Certs.Material(ctx, row.CertID, versionID, needsKey)
	if err != nil {
		return d.fail(ctx, row, versionID, seq, secrets, err)
	}

	files, err := d.renderFiles(ctx, row, m, needsKey)
	if err != nil {
		return d.fail(ctx, row, versionID, seq, secrets, err)
	}

	config, err := targets.Merge(row.TargetConfig, secrets)
	if err != nil {
		return d.fail(ctx, row, versionID, seq, secrets, err)
	}

	req := targets.Request{
		GrantID:     grantID.String(),
		OrgSlug:     row.OrgSlug,
		CertID:      row.CertID.String(),
		CertName:    row.CertificateName,
		Names:       append([]string{row.CertificateCommonName}, row.CertificateSans...),
		Fingerprint: agentproto.CertFingerprint(m.LeafDER),
		Material:    &m,
		Files:       files,
		Config:      config,
		Side:        targets.Server,
		HTTP:        d.HTTP(ctx),
	}
	if _, err := target.Deploy(ctx, req); err != nil {
		return d.fail(ctx, row, versionID, seq, secrets, err)
	}
	return d.Q.MarkServerDeploymentDeployed(ctx, sqlcgen.MarkServerDeploymentDeployedParams{GrantID: grantID, VersionID: &versionID, DeploySeq: seq})
}

// openTargetSecrets opens sealed (a deploy target's secret_cfg; nil/empty
// for a target with no stored secrets) into its decrypted secret map,
// mirroring internal/api/delivery.go's targetSecrets — the established
// pattern for a *_cfg column of this shape.
func (d *Dispatcher) openTargetSecrets(ctx context.Context, sealed []byte) (map[string]string, error) {
	if len(sealed) == 0 {
		return map[string]string{}, nil
	}
	pt, err := d.Box.Open(ctx, sealed)
	if err != nil {
		return nil, err
	}
	var m map[string]string
	if err := json.Unmarshal(pt, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// renderFiles renders a server grant's own certificate material: its
// layout's files (PEM-only, enforced at grant create/update time) when it
// has one, or the four canonical PEM parts otherwise — the "key" part only
// when includeKey (Deploy.Request's own doc comment).
func (d *Dispatcher) renderFiles(ctx context.Context, row sqlcgen.ServerDeployGrantRow, m render.Material, includeKey bool) ([]render.File, error) {
	if len(row.LayoutFiles) == 0 {
		parts := []string{"fullchain", "cert", "chain"}
		if includeKey {
			parts = append(parts, "key")
		}
		return render.PEM{}.Render(m, render.OutputOpts{Parts: parts})
	}
	var specs []delivery.OutputFile
	if err := json.Unmarshal(row.LayoutFiles, &specs); err != nil {
		return nil, err
	}
	extras := map[uuid.UUID]render.Material{}
	if len(row.LayoutExtraCertIds) > 0 {
		vrows, err := d.Q.CurrentVersionsForCerts(ctx, uniq(row.LayoutExtraCertIds))
		if err != nil {
			return nil, err
		}
		byID := map[uuid.UUID]*uuid.UUID{}
		for _, v := range vrows {
			byID[v.ID] = v.CurrentVersionID
		}
		for _, eid := range row.LayoutExtraCertIds {
			vid := byID[eid]
			if vid == nil {
				return nil, fmt.Errorf("deploy: extra certificate %s has no current version", eid)
			}
			em, err := d.Certs.Material(ctx, eid, *vid, false)
			if err != nil {
				return nil, err
			}
			extras[eid] = em
		}
	}
	// Password is never read: RenderLayout only uses it for p12/jks
	// output, and a server grant's layout is PEM-only (enforced when the
	// grant's layoutId is set, both at create and update). A server grant
	// deploys through its own Target.Deploy, not a FileTarget, so this
	// only ever needs the layout's own files.
	layout := &delivery.Layout{Files: specs, ExtraCertIDs: row.LayoutExtraCertIds}
	dfiles, err := delivery.GrantFiles(&m, extras, layout)
	if err != nil {
		return nil, err
	}
	return toRenderFiles(dfiles, specs), nil
}

// toRenderFiles converts a layout's rendered delivery.File (path-addressed,
// for an agent to write) into targets.Request's render.File shape
// (name-addressed, matching a plain PEM render): Name is the rendered
// path's base name, and Secret is derived from the same output spec's own
// format/parts (delivery.NeedsKey on that one file) since delivery.File
// itself carries no such flag.
func toRenderFiles(dfiles []delivery.File, specs []delivery.OutputFile) []render.File {
	out := make([]render.File, len(dfiles))
	for i, f := range dfiles {
		var secret bool
		if i < len(specs) {
			secret = delivery.NeedsKey([]delivery.OutputFile{specs[i]})
		}
		out[i] = render.File{Name: path.Base(f.Path), Data: f.Data, Secret: secret}
	}
	return out
}

// fail records a redacted, truncated last_error on server_deployments
// (scoped to versionID, the version this attempt was for —
// MarkServerDeploymentFailed is a no-op if a newer version has since taken
// over, same reasoning as Deploy's own guard) and returns the same
// redacted message for river to retry on — never cause itself (batch 2
// review, finding 1): river's job executor logs a failed job's error and
// stores it in river_job.errors, so returning the raw cause would leak a
// target secret into both, even though last_error itself was already
// redacted. secrets is this attempt's decrypted target secret map (nil
// before it has been opened, or when opening it is itself what failed) —
// targets.Redact strips every non-empty value of it, and each one's
// base64 form, from cause's message before it is ever stored or returned
// (Global Constraints, Secrets row); a Target implementation may
// additionally run its own redaction (vault-kv: (*vault.Client).Redact)
// before returning an error, which only makes this a second pass. A
// failure to write the record is only logged: the job's own error
// (returned) is what actually drives the retry. row is the same row Deploy
// already fetched (every call site has it in scope): its ID/OrgID/
// CertificateName/TargetName feed the immediate deploy.failed emit below,
// so fail takes it instead of a bare grantID.
func (d *Dispatcher) fail(ctx context.Context, row sqlcgen.ServerDeployGrantRow, versionID uuid.UUID, seq int64, secrets map[string]string, cause error) error {
	msg := targets.Redact(cause, secrets, maxLastError)
	if err := d.Q.MarkServerDeploymentFailed(ctx, sqlcgen.MarkServerDeploymentFailedParams{
		GrantID: row.ID, VersionID: &versionID, DeploySeq: seq, LastError: msg}); err != nil {
		d.log().Error("deploy: server deployment failure not recorded", "grant", row.ID, "err", err)
	}
	// The immediate emit (task-7 brief, Deviations R7) uses the exact same
	// DedupeKey as notify/scan.go's ScanFailedServerDeployments
	// ("deploy.failed:<grantID>:<versionID>"), so the two dedupe to one
	// notification_events row regardless of which fires first. An emit
	// error is only logged: Emit itself already committed (or rolled back)
	// its own transaction, so there is nothing here to undo, and river's
	// retry is driven by the returned error below, not by this.
	if d.Events != nil {
		if err := d.Events.DeployFailed(ctx, DeployFailure{
			OrgID: row.OrgID, GrantID: row.ID, VersionID: versionID,
			CertName: row.CertificateName, TargetName: row.TargetName, LastError: msg,
		}); err != nil {
			d.log().Error("deploy: deploy.failed not emitted", "grant", row.ID, "err", err)
		}
	}
	return errors.New(msg)
}

// uniq returns ids with duplicates removed, preserving first occurrence.
func uniq(ids []uuid.UUID) []uuid.UUID {
	seen := make(map[uuid.UUID]bool, len(ids))
	out := make([]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

// compile-time check that Dispatcher satisfies issuance.VersionListener.
var _ interface {
	OnVersion(context.Context, uuid.UUID, uuid.UUID)
} = (*Dispatcher)(nil)
