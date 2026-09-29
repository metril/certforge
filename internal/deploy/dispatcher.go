package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/render"
)

// maxLastError bounds server_deployments.last_error (Shared contract:
// ServerDeployment.lastError, <= 1000 chars).
const maxLastError = 1000

// DeployArgs is the river job that deploys one server grant's certificate
// material to its target.
type DeployArgs struct {
	GrantID   uuid.UUID `json:"grant_id"`
	VersionID uuid.UUID `json:"version_id"`
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

// Dispatcher is the server-side counterpart to an enrolled agent for
// client-less grants: it hears about every new certificate version
// (issuance.VersionListener), enqueues certforge_server_deploy for each
// live server grant of that certificate, and its DeployWorker renders and
// writes the certificate material to the grant's target.
type Dispatcher struct {
	Pool  *pgxpool.Pool
	Q     *sqlcgen.Queries
	Reg   *Registry
	Certs *certstore.Store
	River Inserter
	Log   *slog.Logger
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
func (d *Dispatcher) ResyncCertificateRename(ctx context.Context, _ *sqlcgen.Queries, certID uuid.UUID) (func(), error) {
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
	if err := q.UpsertServerDeploymentPending(ctx, sqlcgen.UpsertServerDeploymentPendingParams{GrantID: grantID, VersionID: versionID}); err != nil {
		return err
	}
	if versionID == nil {
		return nil
	}
	_, err := d.River.InsertTx(ctx, tx, DeployArgs{GrantID: grantID, VersionID: *versionID}, nil)
	return err
}

// DeployWorker runs DeployArgs.
type DeployWorker struct {
	river.WorkerDefaults[DeployArgs]
	D *Dispatcher
}

// Work implements river.Worker.
func (w *DeployWorker) Work(ctx context.Context, job *river.Job[DeployArgs]) error {
	return w.D.Deploy(ctx, job.Args.GrantID, job.Args.VersionID)
}

// RegisterRiver is an issuance.RiverExtra: DeployWorker, no periodic job.
func (d *Dispatcher) RegisterRiver(workers *river.Workers) []*river.PeriodicJob {
	river.AddWorker(workers, &DeployWorker{D: d})
	return nil
}

// Deploy renders grantID's certificate material at versionID and writes it
// to its target. A grant already removed (row gone, or hard-deleted) is
// simply done: no error, nothing to retry. versionID must still be the
// grant's own pending version (server_deployments.version_id) — a job for
// an older version that finishes after a newer one has already taken over
// (a fresh OnVersion, or a redeploy, moved the grant on) is stale and does
// nothing at all, successfully: overwriting Vault with an old certificate
// and marking it "deployed" would be worse than leaving the newer job to
// run (batch-5 review). Any other failure records a truncated last_error
// on server_deployments and is returned so river retries with backoff.
// DeployWorker.Work calls this for certforge_server_deploy; it is also
// exported for a test to run one deploy attempt directly, without a live
// river client.
func (d *Dispatcher) Deploy(ctx context.Context, grantID, versionID uuid.UUID) error {
	row, err := d.Q.ServerDeployGrant(ctx, grantID)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if row.PendingVersionID == nil || *row.PendingVersionID != versionID {
		return nil
	}
	target, ok := d.Reg.Get(row.TargetType)
	if !ok {
		return d.fail(ctx, grantID, versionID, fmt.Errorf("deploy: unknown target type %q", row.TargetType))
	}
	var cfg map[string]any
	if err := json.Unmarshal(row.TargetConfig, &cfg); err != nil {
		return d.fail(ctx, grantID, versionID, err)
	}
	includeKey, _ := cfg["includeKey"].(bool)

	m, err := d.Certs.Material(ctx, row.CertID, versionID, includeKey)
	if err != nil {
		return d.fail(ctx, grantID, versionID, err)
	}

	files, err := d.renderFiles(ctx, row, m, includeKey)
	if err != nil {
		return d.fail(ctx, grantID, versionID, err)
	}

	if _, err := target.Deploy(ctx, Request{OrgSlug: row.OrgSlug, CertID: row.CertID.String(), CertName: row.CertificateName, Files: files, Config: cfg}); err != nil {
		return d.fail(ctx, grantID, versionID, err)
	}
	return d.Q.MarkServerDeploymentDeployed(ctx, sqlcgen.MarkServerDeploymentDeployedParams{GrantID: grantID, VersionID: &versionID})
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
	// grant's layoutId is set, both at create and update).
	layout := &delivery.Layout{Files: specs, ExtraCertIDs: row.LayoutExtraCertIds}
	names := append([]string{row.CertificateCommonName}, row.CertificateSans...)
	dfiles, err := delivery.GrantFiles(&m, extras, layout, nil, row.CertificateName, names)
	if err != nil {
		return nil, err
	}
	return toRenderFiles(dfiles, specs), nil
}

// toRenderFiles converts a layout's rendered delivery.File (path-addressed,
// for an agent to write) into deploy.Request's render.File shape
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

// fail records a truncated last_error on server_deployments (scoped to
// versionID, the version this attempt was for — MarkServerDeploymentFailed
// is a no-op if a newer version has since taken over, same reasoning as
// Deploy's own guard) and returns cause for river to retry. cause is
// already redacted of any Vault secret by the time it reaches here: every
// internal/vault.Client method a Target implementation (vault-kv) calls
// runs its error through (*vault.Client).Redact before returning it, so
// this only has to bound the length. A failure to write the record is only
// logged: the job's own error (returned) is what actually drives the retry.
func (d *Dispatcher) fail(ctx context.Context, grantID, versionID uuid.UUID, cause error) error {
	msg := truncateUTF8(cause.Error(), maxLastError)
	if err := d.Q.MarkServerDeploymentFailed(ctx, sqlcgen.MarkServerDeploymentFailedParams{
		GrantID: grantID, VersionID: &versionID, LastError: msg}); err != nil {
		d.log().Error("deploy: server deployment failure not recorded", "grant", grantID, "err", err)
	}
	return cause
}

// truncateUTF8 cuts s to at most maxBytes bytes, trimming back further if
// the cut landed inside a multi-byte rune (an incomplete trailing sequence
// makes Postgres reject the string outright, since text columns must be
// valid UTF-8 — losing the whole failure record over a split emoji or
// accented character would defeat the point of recording one at all).
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size != 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
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
