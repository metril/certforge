package agents

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/render"
)

const (
	touchEvery = 10 * time.Second
	seenTTL    = 10 * time.Minute
)

// markSeen records a sighting of id and reports whether last_seen is due a
// write (none in the last touchEvery). Entries idle for seenTTL are pruned,
// at most once per seenTTL, so deleted or revoked clients do not accumulate.
func (s *Service) markSeen(id uuid.UUID, now time.Time) bool {
	s.seenMu.Lock()
	defer s.seenMu.Unlock()
	if s.seen == nil {
		s.seen = map[uuid.UUID]time.Time{}
	}
	if now.Sub(s.seenPruned) >= seenTTL {
		for k, t := range s.seen {
			if now.Sub(t) >= seenTTL {
				delete(s.seen, k)
			}
		}
		s.seenPruned = now
	}
	if now.Sub(s.seen[id]) < touchEvery {
		return false
	}
	s.seen[id] = now
	return true
}

// touch writes last_seen at most every touchEvery per client.
func (s *Service) touch(ctx context.Context, id uuid.UUID) {
	if !s.markSeen(id, s.now()) {
		return
	}
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
	rows, err := s.Q.ClientAssignments(ctx, &c.ID)
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
		var target *agentproto.Target
		if r.TargetType != nil {
			secrets, err := s.openTargetSecrets(ctx, r.TargetSecretCfg)
			if err != nil {
				return agentproto.Assignments{}, err
			}
			if target, err = targetOf(r.TargetType, r.TargetConfig, secrets); err != nil {
				return agentproto.Assignments{}, err
			}
		}
		if r.RemovedAt != nil {
			paths := make([]string, 0, len(specs))
			for _, f := range specs {
				paths = append(paths, f.Path)
			}
			out.Removed = append(out.Removed, agentproto.Removal{ID: r.ID, Files: paths, Target: target})
			continue
		}
		// A version-less certificate (C3) is still worth listing when its
		// last render found target files to install (the Traefik ACME
		// router file, gated on acmeServiceUrl by GrantFiles/agents.render);
		// otherwise it is skipped exactly as before this grant could ever
		// have anything to install.
		if r.VersionID == nil && len(specs) == 0 {
			continue
		}
		names := append([]string{r.CertificateCommonName}, r.CertificateSans...)
		a := agentproto.Assignment{ID: r.ID, CertificateID: r.CertID, CertificateName: r.CertificateName, CertificateNames: names, VersionID: r.VersionID,
			RedeploySeq: r.RedeploySeq, Delivery: r.Delivery, Files: specs, Target: target, Hooks: []agentproto.HookSpec{}}
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
	r, err := s.Q.GrantForBundle(ctx, sqlcgen.GrantForBundleParams{ID: grantID, ClientID: &c.ID})
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
		var files []delivery.OutputFile
		if err := json.Unmarshal(r.LayoutFiles, &files); err != nil {
			return agentproto.Bundle{}, err
		}
		password, err := s.openPassword(ctx, r.LayoutPassword)
		if err != nil {
			return agentproto.Bundle{}, err
		}
		// Extras render from the deployment's own extra_version_ids (the
		// versions actually last rendered into this grant's expected
		// digests), never the extra certificates' current versions: a
		// bundle must match what the server already told the agent to
		// expect, even when an extra certificate has since gained a newer
		// version that no resync has picked up yet.
		if len(r.LayoutExtraCertIds) != len(r.ExtraVersionIds) {
			return agentproto.Bundle{}, fmt.Errorf("agents: grant %s: layout has %d extra certificates but %d rendered versions",
				grantID, len(r.LayoutExtraCertIds), len(r.ExtraVersionIds))
		}
		extras := map[uuid.UUID]render.Material{}
		for i, eid := range r.LayoutExtraCertIds {
			em, err := s.Certs.Material(ctx, eid, r.ExtraVersionIds[i], false)
			if err != nil {
				return agentproto.Bundle{}, err
			}
			extras[eid] = em
		}
		layout := delivery.Layout{Files: files, ExtraCertIDs: r.LayoutExtraCertIds, Password: password}
		rendered, err := delivery.RenderLayout(m, extras, layout)
		if err != nil {
			return agentproto.Bundle{}, err
		}
		for _, f := range rendered {
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
	rows, err := q.ClientDeployments(ctx, &c.ID)
	if err != nil {
		return err
	}
	byGrant := make(map[uuid.UUID]sqlcgen.ClientDeploymentsRow, len(rows))
	for _, r := range rows {
		byGrant[r.GrantID] = r
	}
	var events []audit.Event
	var remediateGrants []uuid.UUID
	pushRemediate := false
	for _, res := range rep.Results {
		d, ok := byGrant[res.GrantID]
		if !ok {
			continue
		}
		if d.RemovedAt != nil {
			// Only a removal result confirms: no version (a deploy result
			// always names one) and a revision at or past the one that
			// announced the removal, so a deploy result for assignments
			// fetched before the delete cannot delete the row while the
			// files are still on the host.
			if res.State == agentproto.StateOK && res.VersionID == uuid.Nil && rep.Revision >= d.RemovedRevision {
				if err := q.DeleteGrantRow(ctx, d.GrantID); err != nil {
					return err
				}
			}
			continue
		}
		// A result for an older version changes no deployment state, but
		// its hook runs still happened and are kept as history below. A
		// version-less deployment (C3) has no version to match: the agent
		// reports it with a zero-value VersionID (it never fetches a
		// Bundle for one), so it matches the same way uuid.Nil already
		// signals "no version" for a removal's confirmation above.
		sameVersion := (d.VersionID == nil && res.VersionID == uuid.Nil) || (d.VersionID != nil && res.VersionID == *d.VersionID)
		if sameVersion {
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
					remediateGrants = append(remediateGrants, d.GrantID)
					pushRemediate = pushRemediate || d.Delivery == "push"
				}
			}
		}
		for _, hr := range res.HookRuns {
			if hr.Phase != "pre_deploy" && hr.Phase != "post_deploy" {
				s.log().Warn("agents: hook run with an unknown phase rejected", "client", c.ID, "grant", d.GrantID, "phase", hr.Phase)
				continue
			}
			argv := make([]string, 0, len(hr.Argv))
			for _, a := range hr.Argv {
				argv = append(argv, clip(a, 4096))
			}
			phase := clip(hr.Phase, 32)
			if err := q.InsertHookRun(ctx, sqlcgen.InsertHookRunParams{ClientID: c.ID, GrantID: d.GrantID, HookID: hr.HookID, OrgID: c.OrgID,
				Phase: phase, Argv: argv, ExitCode: int32(hr.ExitCode), DurationMs: hr.DurationMS,
				Stdout: clip(hr.Stdout, 8192), Stderr: clip(hr.Stderr, 8192)}); err != nil {
				return err
			}
			events = append(events, audit.Event{Action: "hook.run", ResourceType: "grant", ResourceID: d.GrantID.String(), OrgID: &c.OrgID,
				Details: map[string]any{"hookId": hr.HookID, "phase": phase, "exitCode": hr.ExitCode, "durationMs": hr.DurationMS}})
		}
	}
	if err := q.SetAppliedRevision(ctx, sqlcgen.SetAppliedRevisionParams{Revision: rep.Revision, ID: c.ID}); err != nil {
		return err
	}
	var revs []sqlcgen.BumpClientRevisionsRow
	if len(remediateGrants) > 0 {
		if err := q.BumpRedeploySeqs(ctx, uniq(remediateGrants)); err != nil {
			return err
		}
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
	rows, err := q.ClientDeployments(ctx, &c.ID)
	if err != nil {
		return err
	}
	var events []audit.Event
	var remediateGrants []uuid.UUID
	pushRemediate := false
	for _, d := range rows {
		// A version-less deployment (C3) is still compared: its expected
		// file set (the ACME router file, or none) is version-independent,
		// so HeartbeatState's cur/expected/installed comparison works the
		// same as any other deployment.
		if d.RemovedAt != nil {
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
			remediateGrants = append(remediateGrants, d.GrantID)
			pushRemediate = pushRemediate || d.Delivery == "push"
		}
	}
	var revs []sqlcgen.BumpClientRevisionsRow
	if len(remediateGrants) > 0 {
		if err := q.BumpRedeploySeqs(ctx, uniq(remediateGrants)); err != nil {
			return err
		}
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
