package agents

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
)

const touchEvery = 10 * time.Second

// touch writes last_seen at most every 10 s per client.
func (s *Service) touch(ctx context.Context, id uuid.UUID) {
	s.seenMu.Lock()
	if s.seen == nil {
		s.seen = map[uuid.UUID]time.Time{}
	}
	now := s.now()
	if now.Sub(s.seen[id]) < touchEvery {
		s.seenMu.Unlock()
		return
	}
	s.seen[id] = now
	s.seenMu.Unlock()
	if err := s.Q.TouchClient(ctx, id); err != nil {
		s.log().Warn("agents: last_seen not written", "client", id, "err", err)
	}
}

func specsOf(raw []byte) ([]agentproto.FileSpec, error) {
	var out []agentproto.FileSpec
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Assignments lists the client's live grants that have a version, plus
// removed grants awaiting confirmation.
func (s *Service) Assignments(ctx context.Context, c sqlcgen.Client) (agentproto.Assignments, error) {
	cur, err := s.Q.GetClientByID(ctx, c.ID)
	if err != nil {
		return agentproto.Assignments{}, err
	}
	rows, err := s.Q.ClientAssignments(ctx, c.ID)
	if err != nil {
		return agentproto.Assignments{}, err
	}
	var hookIDs []uuid.UUID
	for _, r := range rows {
		hookIDs = append(hookIDs, r.HookIds...)
	}
	hooks := map[uuid.UUID]agentproto.HookSpec{}
	if len(hookIDs) > 0 {
		hs, err := s.Q.HooksByIDs(ctx, uniq(hookIDs))
		if err != nil {
			return agentproto.Assignments{}, err
		}
		for _, h := range hs {
			hooks[h.ID] = agentproto.HookSpec{ID: h.ID, Phase: h.Phase, Argv: h.Argv, TimeoutSeconds: int(h.TimeoutSeconds)}
		}
	}
	out := agentproto.Assignments{Revision: cur.DesiredRevision, Grants: []agentproto.Assignment{}, Removed: []agentproto.Removal{}}
	for _, r := range rows {
		specs, err := specsOf(r.Expected)
		if err != nil {
			return agentproto.Assignments{}, err
		}
		target := targetOf(r.TargetType, r.TargetConfig)
		if r.RemovedAt != nil {
			paths := make([]string, 0, len(specs))
			for _, f := range specs {
				paths = append(paths, f.Path)
			}
			out.Removed = append(out.Removed, agentproto.Removal{ID: r.ID, Files: paths, Target: target})
			continue
		}
		if r.VersionID == nil {
			continue
		}
		a := agentproto.Assignment{ID: r.ID, CertificateID: r.CertID, CertificateName: r.CertificateName, VersionID: *r.VersionID,
			Delivery: r.Delivery, Files: specs, Target: target, Hooks: []agentproto.HookSpec{}}
		if r.Fingerprint != nil {
			a.Fingerprint = *r.Fingerprint
		}
		for _, id := range r.HookIds {
			if h, ok := hooks[id]; ok {
				a.Hooks = append(a.Hooks, h)
			}
		}
		out.Grants = append(out.Grants, a)
	}
	s.touch(ctx, c.ID)
	return out, nil
}

// Bundle renders one grant's files for its own agent. Key material leaves
// the server only with an audit row: an audit failure fails the request.
func (s *Service) Bundle(ctx context.Context, c sqlcgen.Client, grantID uuid.UUID) (agentproto.Bundle, error) {
	r, err := s.Q.GrantForBundle(ctx, sqlcgen.GrantForBundleParams{ID: grantID, ClientID: c.ID})
	if errors.Is(err, pgx.ErrNoRows) {
		return agentproto.Bundle{}, notFound("grant %s", grantID)
	}
	if err != nil {
		return agentproto.Bundle{}, err
	}
	if r.VersionID == nil {
		return agentproto.Bundle{}, notFound("grant %s has no issued version yet", grantID)
	}
	m, err := s.Certs.Material(ctx, r.CertID, *r.VersionID, true)
	if err != nil {
		return agentproto.Bundle{}, err
	}
	b := agentproto.Bundle{VersionID: *r.VersionID, Files: []agentproto.BundleFile{}}
	if len(r.LayoutFiles) > 0 {
		var layout []delivery.OutputFile
		if err := json.Unmarshal(r.LayoutFiles, &layout); err != nil {
			return agentproto.Bundle{}, err
		}
		files, err := delivery.RenderLayout(m, layout)
		if err != nil {
			return agentproto.Bundle{}, err
		}
		for _, f := range files {
			b.Files = append(b.Files, agentproto.BundleFile{Path: f.Path, Owner: f.Owner, Group: f.Group, Mode: f.Mode, Content: f.Data})
		}
	}
	if r.TargetType != nil {
		mat, err := delivery.TargetMaterial(m)
		if err != nil {
			return agentproto.Bundle{}, err
		}
		b.Material = &mat
	}
	if s.Auditor != nil {
		if err := s.Auditor.Record(ctx, audit.Event{Action: "grant.bundle_fetched", ResourceType: "grant", ResourceID: grantID.String(),
			OrgID: &c.OrgID, Details: map[string]any{"certificateId": r.CertID, "versionId": *r.VersionID}}); err != nil {
			return agentproto.Bundle{}, err
		}
	}
	return b, nil
}

func deploymentEvent(c sqlcgen.Client, d sqlcgen.ClientDeploymentsRow, state, errText string, missing, mismatched []string) audit.Event {
	return audit.Event{Action: "deployment." + state, ResourceType: "grant", ResourceID: d.GrantID.String(), OrgID: &c.OrgID,
		Details: map[string]any{"clientId": c.ID, "certificateId": d.CertID, "versionId": d.VersionID,
			"previousState": d.State, "error": errText, "missing": missing, "mismatched": mismatched}}
}

func nonNilDigests(in []agentproto.FileDigest) []agentproto.FileDigest {
	if in == nil {
		return []agentproto.FileDigest{}
	}
	return in
}

// Report applies an agent's results: deployment states, hook runs, removal
// confirmations and the applied revision. Results for other clients' or
// older versions are ignored.
func (s *Service) Report(ctx context.Context, c sqlcgen.Client, rep agentproto.Report) error {
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	if _, err := q.LockClientByID(ctx, c.ID); err != nil {
		return err
	}
	rows, err := q.ClientDeployments(ctx, c.ID)
	if err != nil {
		return err
	}
	byGrant := make(map[uuid.UUID]sqlcgen.ClientDeploymentsRow, len(rows))
	for _, r := range rows {
		byGrant[r.GrantID] = r
	}
	var events []audit.Event
	remediate, pushRemediate := false, false
	for _, res := range rep.Results {
		d, ok := byGrant[res.GrantID]
		if !ok {
			continue
		}
		if d.RemovedAt != nil {
			if res.State == agentproto.StateOK {
				if err := q.DeleteGrantRow(ctx, d.GrantID); err != nil {
					return err
				}
			}
			continue
		}
		if d.VersionID == nil || res.VersionID != *d.VersionID {
			continue
		}
		expected, err := specsOf(d.Expected)
		if err != nil {
			return err
		}
		next, errText, missing, mismatched := ReportState(res, expected)
		installed, _ := json.Marshal(nonNilDigests(res.Installed))
		if err := q.SetDeploymentState(ctx, sqlcgen.SetDeploymentStateParams{GrantID: d.GrantID, State: next, Installed: installed, Error: errText}); err != nil {
			return err
		}
		if next != d.State {
			events = append(events, deploymentEvent(c, d, next, errText, missing, mismatched))
			if next == stateDrift && d.AutoRemediate {
				remediate = true
				pushRemediate = pushRemediate || d.Delivery == "push"
			}
		}
		for _, hr := range res.HookRuns {
			argv := make([]string, 0, len(hr.Argv))
			for _, a := range hr.Argv {
				argv = append(argv, clip(a, 4096))
			}
			if err := q.InsertHookRun(ctx, sqlcgen.InsertHookRunParams{ClientID: c.ID, GrantID: d.GrantID, HookID: hr.HookID,
				Phase: clip(hr.Phase, 32), Argv: argv, ExitCode: int32(hr.ExitCode), DurationMs: hr.DurationMS,
				Stdout: clip(hr.Stdout, 8192), Stderr: clip(hr.Stderr, 8192)}); err != nil {
				return err
			}
			events = append(events, audit.Event{Action: "hook.run", ResourceType: "grant", ResourceID: d.GrantID.String(), OrgID: &c.OrgID,
				Details: map[string]any{"hookId": hr.HookID, "phase": hr.Phase, "exitCode": hr.ExitCode, "durationMs": hr.DurationMS}})
		}
	}
	if err := q.SetAppliedRevision(ctx, sqlcgen.SetAppliedRevisionParams{Revision: rep.Revision, ID: c.ID}); err != nil {
		return err
	}
	var revs []sqlcgen.BumpClientRevisionsRow
	if remediate {
		if revs, err = s.bump(ctx, q, []uuid.UUID{c.ID}); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	for _, e := range events {
		s.audit(ctx, e)
	}
	s.nudge(revs, map[uuid.UUID]bool{c.ID: pushRemediate})
	return nil
}

// Heartbeat compares installed files with ok and drifted deployments,
// audits transitions, and bumps the revision for auto-remediating grants.
func (s *Service) Heartbeat(ctx context.Context, c sqlcgen.Client, hb agentproto.Heartbeat) error {
	by := map[uuid.UUID][]agentproto.FileDigest{}
	for _, f := range hb.Installed {
		by[f.GrantID] = append(by[f.GrantID], agentproto.FileDigest{Path: f.Path, SHA256: f.SHA256})
	}
	tx, err := s.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.Q.WithTx(tx)
	if _, err := q.LockClientByID(ctx, c.ID); err != nil {
		return err
	}
	rows, err := q.ClientDeployments(ctx, c.ID)
	if err != nil {
		return err
	}
	var events []audit.Event
	remediate, pushRemediate := false, false
	for _, d := range rows {
		if d.RemovedAt != nil || d.VersionID == nil {
			continue
		}
		expected, err := specsOf(d.Expected)
		if err != nil {
			return err
		}
		next, missing, mismatched := HeartbeatState(d.State, expected, by[d.GrantID])
		if next == d.State {
			continue
		}
		installed, _ := json.Marshal(nonNilDigests(by[d.GrantID]))
		if err := q.SetDeploymentState(ctx, sqlcgen.SetDeploymentStateParams{GrantID: d.GrantID, State: next, Installed: installed, Error: ""}); err != nil {
			return err
		}
		events = append(events, deploymentEvent(c, d, next, "", missing, mismatched))
		if next == stateDrift && d.AutoRemediate {
			remediate = true
			pushRemediate = pushRemediate || d.Delivery == "push"
		}
	}
	var revs []sqlcgen.BumpClientRevisionsRow
	if remediate {
		if revs, err = s.bump(ctx, q, []uuid.UUID{c.ID}); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	for _, e := range events {
		s.audit(ctx, e)
	}
	s.nudge(revs, map[uuid.UUID]bool{c.ID: pushRemediate})
	s.touch(ctx, c.ID)
	return nil
}
