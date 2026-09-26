package agents

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/render"
)

// GrantInput is a grant's settable fields.
type GrantInput struct {
	CertID        uuid.UUID
	Delivery      string
	LayoutID      *uuid.UUID
	TargetID      *uuid.UUID
	HookIDs       []uuid.UUID
	AutoRemediate bool
}

// RefKind names the delivery object whose change triggers Resync.
type RefKind int

// Resync triggers.
const (
	RefLayout RefKind = iota + 1
	RefTarget
	RefHook
)

func (in GrantInput) validate() error {
	if in.Delivery != "push" && in.Delivery != "pull" {
		return invalid("delivery", "delivery must be push or pull")
	}
	if in.LayoutID == nil && in.TargetID == nil {
		return invalid("layoutId", "choose a layout, a deploy target, or both")
	}
	if len(in.HookIDs) > 16 {
		return invalid("hookIds", "a grant runs at most 16 hooks")
	}
	if len(uniq(in.HookIDs)) != len(in.HookIDs) {
		return invalid("hookIds", "each hook may appear once")
	}
	return nil
}

func (in GrantInput) hooks() []uuid.UUID {
	if in.HookIDs == nil {
		return []uuid.UUID{}
	}
	return in.HookIDs
}

func (s *Service) checkRefs(ctx context.Context, q *sqlcgen.Queries, orgID uuid.UUID, in GrantInput) error {
	r, err := q.CheckGrantRefs(ctx, sqlcgen.CheckGrantRefsParams{CertID: in.CertID, OrgID: orgID,
		LayoutID: in.LayoutID, TargetID: in.TargetID, HookIds: in.hooks()})
	if err != nil {
		return err
	}
	switch {
	case !r.CertOk:
		return invalid("certificateId", "certificate %s is not in this org", in.CertID)
	case !r.LayoutOk:
		return invalid("layoutId", "layout %s is not in this org", *in.LayoutID)
	case !r.TargetOk:
		return invalid("deployTargetId", "deploy target %s is not in this org", *in.TargetID)
	case r.HooksFound != int64(len(in.HookIDs)):
		return invalid("hookIds", "every hook must be in this org")
	}
	// hook_ids is a plain array with no FK, so a hook could otherwise be
	// deleted between the check above and the insert below. Lock the
	// referenced hook rows FOR SHARE here, inside the same transaction as
	// the grant write: DeleteHook takes the hook row FOR UPDATE before it
	// re-checks dependents, so the two either serialize with this grant
	// winning (DeleteHook then sees it and refuses) or DeleteHook wins and
	// this recount below catches the now-missing hook.
	//
	// checkRefs runs, and so takes these locks, before CreateGrant/UpdateGrant
	// lock the client row: see the package comment for the global lock
	// order (referenced rows, then client, then deployments). Locking hooks
	// here first matters because a hook update (internal/api.UpdateHook)
	// locks the hook row before it locks affected clients via Resync; if a
	// grant write locked the client first and hooks second, the two could
	// deadlock (AB-BA).
	if len(in.HookIDs) > 0 {
		locked, err := q.LockHooksInOrg(ctx, sqlcgen.LockHooksInOrgParams{Ids: in.hooks(), OrgID: orgID})
		if err != nil {
			return err
		}
		if len(uniq(locked)) != len(uniq(in.HookIDs)) {
			return invalid("hookIds", "every hook must be in this org")
		}
	}
	// output_spec_id and deploy_target_id are real FKs: an insert/update
	// that sets them would otherwise take this lock implicitly, at whatever
	// point the statement runs (in CreateGrant, after the client lock).
	// Locking them explicitly here, before the client, matches a layout or
	// deploy target update, which locks its own row before locking affected
	// clients via Resync; without this a grant write and a layout/target
	// update could deadlock the same way as the hook case above. The lock
	// mode matters too: LockLayoutForGrant/LockTargetForGrant take FOR
	// SHARE, which actually conflicts with an UPDATE's implicit FOR NO KEY
	// UPDATE (FOR KEY SHARE would not: Postgres treats it as compatible
	// with FOR NO KEY UPDATE), so a layout/target PATCH and a grant
	// create/update referencing the same row always serialize instead of
	// each proceeding unaware of the other.
	if in.LayoutID != nil {
		if _, err := q.LockLayoutForGrant(ctx, sqlcgen.LockLayoutForGrantParams{ID: *in.LayoutID, OrgID: orgID}); errors.Is(err, pgx.ErrNoRows) {
			return invalid("layoutId", "layout %s is not in this org", *in.LayoutID)
		} else if err != nil {
			return err
		}
	}
	if in.TargetID != nil {
		if _, err := q.LockTargetForGrant(ctx, sqlcgen.LockTargetForGrantParams{ID: *in.TargetID, OrgID: orgID}); errors.Is(err, pgx.ErrNoRows) {
			return invalid("deployTargetId", "deploy target %s is not in this org", *in.TargetID)
		} else if err != nil {
			return err
		}
	}
	return nil
}

func targetOf(typ *string, cfg []byte) *agentproto.Target {
	if typ == nil {
		return nil
	}
	return &agentproto.Target{Type: *typ, Config: json.RawMessage(cfg)}
}

// grantPaths lists the paths a live grant writes (layout files, then the
// Traefik target's certs/<SafeName>/* and YAML); it needs no key material.
func grantPaths(layoutFiles []byte, typ *string, cfg []byte, certName string) ([]string, error) {
	var out []string
	if len(layoutFiles) > 0 {
		var layout []delivery.OutputFile
		if err := json.Unmarshal(layoutFiles, &layout); err != nil {
			return nil, err
		}
		for _, f := range layout {
			out = append(out, f.Path)
		}
	}
	if typ != nil {
		tc, err := delivery.ParseTarget(*typ, cfg)
		if err != nil {
			return nil, err
		}
		for _, f := range delivery.RenderTraefik(certName, tc, nil, nil) {
			out = append(out, f.Path)
		}
	}
	return out, nil
}

// checkPaths refuses a change that makes two grants of one client write the
// same path: the agent would delete one grant's files while removing the
// other's. Grants awaiting removal count with the paths they last rendered;
// certificate names that share a SafeName collide on Traefik paths.
func (s *Service) checkPaths(ctx context.Context, q *sqlcgen.Queries, clientIDs []uuid.UUID) error {
	if len(clientIDs) == 0 {
		return nil
	}
	rows, err := q.ClientGrantPaths(ctx, uniq(clientIDs))
	if err != nil {
		return err
	}
	owner := map[string]string{}
	for _, r := range rows {
		var paths []string
		if r.RemovedAt != nil {
			var specs []agentproto.FileSpec
			if len(r.Expected) > 0 {
				if err := json.Unmarshal(r.Expected, &specs); err != nil {
					return err
				}
			}
			for _, f := range specs {
				paths = append(paths, f.Path)
			}
			// expected is empty when this grant's certificate had no
			// current version at its last render (never actually
			// installed), which would otherwise let a removed grant
			// contribute zero paths and silently release its layout/target
			// paths for another grant to claim. Fall back to the paths its
			// current layout/target definition would write; layout/target
			// rows are never deleted while a grant (including a
			// removal-pending one) still references them, so this is
			// always available.
			if len(specs) == 0 {
				if paths, err = grantPaths(r.LayoutFiles, r.TargetType, r.TargetConfig, r.CertificateName); err != nil {
					return err
				}
			}
		} else if paths, err = grantPaths(r.LayoutFiles, r.TargetType, r.TargetConfig, r.CertificateName); err != nil {
			return err
		}
		for _, p := range paths {
			k := r.ClientID.String() + "\x00" + p
			if other, ok := owner[k]; ok {
				return conflict("The grants for %q and %q on this client would both write %s; use a different layout path or deploy target.", other, r.CertificateName, p)
			}
			owner[k] = r.CertificateName
		}
	}
	return nil
}

// render recomputes the expected files of grantIDs from their certificate's
// current version and resets their deployments to pending. It returns the
// affected clients and which of them have a push grant among these.
//
// It locks every affected client FOR UPDATE, in id order, before writing
// any deployment row: every caller that writes deployments does so through
// render, so this is the one place a client-row lock happens before a
// deployment-row lock, everywhere. CreateGrant/UpdateGrant already hold
// their single client's lock by the time they call render (re-locking the
// same row here is a no-op); resyncTx (layout/target/hook changes, OnVersion,
// the sweep) does not lock any client beforehand, so without this the two
// families would take the same two locks in opposite orders and could
// deadlock. Locking here first also closes the race where checkPaths reads
// a client's grants without holding its lock: by the time render returns,
// every affected client is locked for the rest of the transaction, so a
// concurrent CreateGrant/UpdateGrant on the same client blocks until this
// transaction commits or rolls back, instead of both computing checkPaths
// against a stale, pre-conflict view.
//
// Full lock order across this package: the grant row itself FOR UPDATE
// first (when the path starts from a grant), then referenced rows (hooks,
// layout/target, certificate), then client rows in id order (here), then
// deployments.
func (s *Service) render(ctx context.Context, q *sqlcgen.Queries, grantIDs []uuid.UUID) ([]uuid.UUID, map[uuid.UUID]bool, error) {
	rows, err := q.GrantSources(ctx, grantIDs)
	if err != nil {
		return nil, nil, err
	}
	clients := make([]uuid.UUID, 0, len(rows))
	for _, r := range rows {
		clients = append(clients, r.ClientID)
	}
	clients = uniq(clients)
	if len(clients) > 0 {
		if _, err := q.LockClientsByID(ctx, clients); err != nil {
			return nil, nil, err
		}
	}
	push := map[uuid.UUID]bool{}
	materials := map[uuid.UUID]render.Material{}
	for _, r := range rows {
		if r.Delivery == "push" {
			push[r.ClientID] = true
		}
		expected := []byte("[]")
		if r.CurrentVersionID != nil {
			m, ok := materials[*r.CurrentVersionID]
			if !ok {
				if m, err = s.Certs.Material(ctx, r.CertID, *r.CurrentVersionID, true); err != nil {
					return nil, nil, err
				}
				materials[*r.CurrentVersionID] = m
			}
			var layout []delivery.OutputFile
			if len(r.LayoutFiles) > 0 {
				if err := json.Unmarshal(r.LayoutFiles, &layout); err != nil {
					return nil, nil, err
				}
			}
			files, err := delivery.GrantFiles(m, layout, targetOf(r.TargetType, r.TargetConfig), r.CertificateName)
			if err != nil {
				return nil, nil, err
			}
			if expected, err = json.Marshal(delivery.Specs(files)); err != nil {
				return nil, nil, err
			}
		}
		if err := q.UpsertDeployment(ctx, sqlcgen.UpsertDeploymentParams{GrantID: r.ID, VersionID: r.CurrentVersionID, Expected: expected}); err != nil {
			return nil, nil, err
		}
	}
	return clients, push, nil
}

func grantDetails(g sqlcgen.ClientCertGrant) map[string]any {
	return map[string]any{"clientId": g.ClientID, "certificateId": g.CertID, "delivery": g.Delivery,
		"layoutId": g.OutputSpecID, "deployTargetId": g.DeployTargetID, "hookIds": g.HookIds, "autoRemediate": g.AutoRemediate}
}

func (s *Service) lockGrant(ctx context.Context, q *sqlcgen.Queries, orgID, id uuid.UUID) (sqlcgen.ClientCertGrant, error) {
	g, err := q.LockGrant(ctx, sqlcgen.LockGrantParams{ID: id, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return g, notFound("grant %s", id)
	}
	return g, err
}

// CreateGrant grants a certificate to a client and bumps its revision.
func (s *Service) CreateGrant(ctx context.Context, orgID, clientID uuid.UUID, in GrantInput) (uuid.UUID, error) {
	if err := in.validate(); err != nil {
		return uuid.Nil, err
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	// Referenced rows lock first, the client last (package comment): hooks
	// and layout/target here, then the certificate, then the client below.
	if err := s.checkRefs(ctx, q, orgID, in); err != nil {
		return uuid.Nil, err
	}
	// Locks the certificate FOR KEY SHARE before inserting a row that
	// references it: FOR KEY SHARE conflicts with DeleteCertificate's FOR
	// UPDATE, so the two serialize instead of a delete racing this insert
	// (checkRefs's existence check alone is not enough: the certificate
	// could be deleted between that check and the insert). Also serializes
	// against a certificate rename (UpdateCertificate's GetCertificateForUpdate,
	// also FOR UPDATE).
	if _, err := q.LockCertificateForGrant(ctx, sqlcgen.LockCertificateForGrantParams{ID: in.CertID, OrgID: orgID}); errors.Is(err, pgx.ErrNoRows) {
		return uuid.Nil, invalid("certificateId", "certificate %s is not in this org", in.CertID)
	} else if err != nil {
		return uuid.Nil, err
	}
	c, err := s.lockClient(ctx, q, orgID, clientID)
	if err != nil {
		return uuid.Nil, err
	}
	if c.Status == "revoked" {
		return uuid.Nil, conflict("Revoked clients cannot receive grants.")
	}
	g, err := q.CreateGrant(ctx, sqlcgen.CreateGrantParams{ClientID: clientID, CertID: in.CertID, Delivery: in.Delivery,
		OutputSpecID: in.LayoutID, DeployTargetID: in.TargetID, HookIds: in.hooks(), AutoRemediate: in.AutoRemediate})
	if pgCode(err) == pgUniqueViolation {
		return uuid.Nil, conflict("This client already has a grant for that certificate.")
	}
	if err != nil {
		return uuid.Nil, err
	}
	if err := s.checkPaths(ctx, q, []uuid.UUID{clientID}); err != nil {
		return uuid.Nil, err
	}
	_, push, err := s.render(ctx, q, []uuid.UUID{g.ID})
	if err != nil {
		return uuid.Nil, err
	}
	revs, err := s.bump(ctx, q, []uuid.UUID{clientID})
	if err != nil {
		return uuid.Nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return uuid.Nil, err
	}
	s.nudge(revs, push)
	s.audit(ctx, audit.Event{Action: "grant.create", ResourceType: "grant", ResourceID: g.ID.String(), OrgID: &orgID, Details: grantDetails(g)})
	return g.ID, nil
}

// UpdateGrant replaces a grant's delivery settings (not its certificate).
func (s *Service) UpdateGrant(ctx context.Context, orgID, grantID uuid.UUID, in GrantInput) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	cur, err := s.lockGrant(ctx, q, orgID, grantID)
	if err != nil {
		return err
	}
	in.CertID = cur.CertID
	if err := in.validate(); err != nil {
		return err
	}
	// Referenced rows (hooks, layout/target) lock before the client, same
	// order as CreateGrant; the certificate itself is not locked here since
	// UpdateGrant never changes it.
	if err := s.checkRefs(ctx, q, orgID, in); err != nil {
		return err
	}
	if _, err := q.LockClientByID(ctx, cur.ClientID); err != nil {
		return err
	}
	g, err := q.UpdateGrant(ctx, sqlcgen.UpdateGrantParams{Delivery: in.Delivery, OutputSpecID: in.LayoutID,
		DeployTargetID: in.TargetID, HookIds: in.hooks(), AutoRemediate: in.AutoRemediate, ID: grantID})
	if err != nil {
		return err
	}
	if err := s.checkPaths(ctx, q, []uuid.UUID{g.ClientID}); err != nil {
		return err
	}
	_, push, err := s.render(ctx, q, []uuid.UUID{grantID})
	if err != nil {
		return err
	}
	revs, err := s.bump(ctx, q, []uuid.UUID{g.ClientID})
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.nudge(revs, push)
	s.audit(ctx, audit.Event{Action: "grant.update", ResourceType: "grant", ResourceID: grantID.String(), OrgID: &orgID,
		Details: map[string]any{"before": grantDetails(cur), "after": grantDetails(g)}})
	return nil
}

// DeleteGrant queues the grant's files for removal by an enrolled agent, or
// deletes it at once when no agent can act on it.
func (s *Service) DeleteGrant(ctx context.Context, orgID, grantID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	g, err := s.lockGrant(ctx, q, orgID, grantID)
	if err != nil {
		return err
	}
	c, err := q.GetClientByID(ctx, g.ClientID)
	if err != nil {
		return err
	}
	// A revoked client, or a pending one that never applied a revision
	// (never enrolled, or enrolled but never actually deployed anything),
	// has no agent that could ever remove this grant's files, so the row
	// is deleted at once. A pending client with applied_revision > 0 has
	// deployed before (it was active, then re-enrolled or its certificate
	// expired and it dropped back to pending) and may still have files on
	// disk from this grant, so it keeps the soft-delete path: the row
	// stays removal-pending until that client reconnects and reports the
	// files gone.
	immediate := c.Status == "revoked" || (c.Status == "pending" && c.AppliedRevision == 0)
	var revs []sqlcgen.BumpClientRevisionsRow
	if immediate {
		err = q.DeleteGrantRow(ctx, grantID)
	} else if revs, err = s.bump(ctx, q, []uuid.UUID{g.ClientID}); err == nil && len(revs) != 1 {
		err = errors.New("agents: bump returned no revision for the grant's client")
	} else if err == nil {
		// The bumped revision is the first one whose assignments list this
		// grant under removed[]; Report only confirms the removal from a
		// report at or past it.
		err = q.MarkGrantRemoved(ctx, sqlcgen.MarkGrantRemovedParams{ID: grantID, RemovedRevision: revs[0].DesiredRevision})
	}
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.nudge(revs, map[uuid.UUID]bool{g.ClientID: g.Delivery == "push"})
	d := grantDetails(g)
	d["immediate"] = immediate
	s.audit(ctx, audit.Event{Action: "grant.delete", ResourceType: "grant", ResourceID: grantID.String(), OrgID: &orgID, Details: d})
	return nil
}

// Redeploy marks a grant pending and nudges its agent.
func (s *Service) Redeploy(ctx context.Context, orgID, grantID uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	g, err := s.lockGrant(ctx, q, orgID, grantID)
	if err != nil {
		return err
	}
	_, push, err := s.render(ctx, q, []uuid.UUID{grantID})
	if err != nil {
		return err
	}
	revs, err := s.bump(ctx, q, []uuid.UUID{g.ClientID})
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	s.nudge(revs, push)
	s.audit(ctx, audit.Event{Action: "grant.redeploy", ResourceType: "grant", ResourceID: grantID.String(), OrgID: &orgID,
		Details: map[string]any{"clientId": g.ClientID, "certificateId": g.CertID}})
	return nil
}

// resyncTx re-renders ids and bumps their clients inside the caller's
// transaction; the caller runs the returned nudge after commit.
func (s *Service) resyncTx(ctx context.Context, q *sqlcgen.Queries, ids []uuid.UUID, checkPaths bool) (func(), error) {
	if len(ids) == 0 {
		return func() {}, nil
	}
	clients, push, err := s.render(ctx, q, ids)
	if err != nil {
		return nil, err
	}
	if checkPaths {
		if err := s.checkPaths(ctx, q, clients); err != nil {
			return nil, err
		}
	}
	revs, err := s.bump(ctx, q, clients)
	if err != nil {
		return nil, err
	}
	return func() { s.nudge(revs, push) }, nil
}

// resyncGrantsOneClient re-renders one client's grants in their own
// transaction.
func (s *Service) resyncGrantsOneClient(ctx context.Context, ids []uuid.UUID) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	nudge, err := s.resyncTx(ctx, s.Q.WithTx(tx), ids, false)
	if err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	nudge()
	return nil
}

// resyncGrants re-renders ids, one transaction per client: OnVersion and
// SweepDeployments can be asked to re-render grants of many clients at
// once, and a render failure for one client (for example a corrupted
// deploy target config) must not roll back or delay every other client's
// already-computed update. Every client is attempted; the first error is
// returned (so the caller still knows something needs attention and, for
// SweepDeployments, river retries), but only after every client has had
// its own chance to commit.
func (s *Service) resyncGrants(ctx context.Context, ids []uuid.UUID) error {
	if len(ids) == 0 {
		return nil
	}
	groups, err := s.Q.GrantClientIDs(ctx, ids)
	if err != nil {
		return err
	}
	byClient := map[uuid.UUID][]uuid.UUID{}
	for _, g := range groups {
		byClient[g.ClientID] = append(byClient[g.ClientID], g.ID)
	}
	var firstErr error
	for clientID, grantIDs := range byClient {
		if err := s.resyncGrantsOneClient(ctx, grantIDs); err != nil {
			s.log().Error("agents: re-render failed for one client; continuing with the rest", "client", clientID, "err", err)
			if firstErr == nil {
				firstErr = err
			}
		}
	}
	return firstErr
}

// Resync re-renders every live grant using a changed layout, target or hook
// inside q, the transaction that made the change, so the change and its
// deployments commit together (R7). A layout or target change that makes
// two of a client's grants write one path fails with a conflict. The caller
// runs the returned nudge after commit.
func (s *Service) Resync(ctx context.Context, q *sqlcgen.Queries, ref RefKind, id uuid.UUID) (func(), error) {
	var ids []uuid.UUID
	var err error
	switch ref {
	case RefLayout:
		ids, err = q.LiveGrantIDsUsingLayout(ctx, &id)
	case RefTarget:
		ids, err = q.LiveGrantIDsUsingTarget(ctx, &id)
	case RefHook:
		ids, err = q.LiveGrantIDsUsingHook(ctx, id)
	}
	if err != nil {
		return nil, err
	}
	return s.resyncTx(ctx, q, ids, ref != RefHook)
}

// ResyncCertificateRename re-renders every live grant of certID inside q,
// the transaction that just renamed the certificate (issuance.Store's
// UpdateCertificate rename hook): a Traefik target's generated files live
// under certs/<SafeName(certificate name)>, so a rename can both make two
// of a client's grants collide (checked, 409 fails the rename) and leaves
// deployments.expected holding stale pre-rename paths until something
// re-renders them. The caller runs the returned nudge after commit.
func (s *Service) ResyncCertificateRename(ctx context.Context, q *sqlcgen.Queries, certID uuid.UUID) (func(), error) {
	ids, err := q.LiveGrantIDsForCert(ctx, certID)
	if err != nil {
		return nil, err
	}
	return s.resyncTx(ctx, q, ids, true)
}

// OnVersion implements issuance.VersionListener: every live grant of the
// certificate gets the new version's digests and its agent a nudge.
func (s *Service) OnVersion(ctx context.Context, certID, versionID uuid.UUID) {
	ids, err := s.Q.LiveGrantIDsForCert(ctx, certID)
	if err == nil {
		err = s.resyncGrants(ctx, ids)
	}
	if err != nil {
		s.log().Error("agents: deployments not updated for a new certificate version; the hourly sweep retries", "cert", certID, "version", versionID, "err", err)
	}
}

// SweepDeployments re-renders every live grant whose deployment is not on
// its certificate's current version. It covers an OnVersion that failed, or
// never ran because the process stopped after the issuance commit.
func (s *Service) SweepDeployments(ctx context.Context) error {
	ids, err := s.Q.StaleDeploymentGrantIDs(ctx)
	if err != nil {
		return err
	}
	if len(ids) > 0 {
		s.log().Info("agents: re-rendering deployments behind their certificate's current version", "grants", len(ids))
	}
	return s.resyncGrants(ctx, ids)
}

// SweepArgs is the hourly river job that runs SweepDeployments.
type SweepArgs struct{}

// Kind is the river job kind.
func (SweepArgs) Kind() string { return "certforge_agent_deployment_sweep" }

// SweepWorker runs SweepArgs.
type SweepWorker struct {
	river.WorkerDefaults[SweepArgs]
	S *Service
}

// Work runs one sweep.
func (w *SweepWorker) Work(ctx context.Context, _ *river.Job[SweepArgs]) error {
	return w.S.SweepDeployments(ctx)
}

// RegisterRiver is an issuance.RiverExtra: the sweep worker and its hourly job.
func (s *Service) RegisterRiver(workers *river.Workers) []*river.PeriodicJob {
	river.AddWorker(workers, &SweepWorker{S: s})
	return []*river.PeriodicJob{river.NewPeriodicJob(river.PeriodicInterval(time.Hour),
		func() (river.JobArgs, *river.InsertOpts) { return SweepArgs{}, nil }, nil)}
}

// compile-time check that Service satisfies issuance.VersionListener.
var _ interface {
	OnVersion(context.Context, uuid.UUID, uuid.UUID)
} = (*Service)(nil)
