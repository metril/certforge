package agent

import (
	"context"
	"log/slog"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
)

// API is what reconciling needs from the server (Client implements it).
type API interface {
	Assignments(ctx context.Context) (agentproto.Assignments, error)
	Bundle(ctx context.Context, grantID uuid.UUID) (agentproto.Bundle, error)
}

// Reconciler makes the host match the server's assignments.
type Reconciler struct {
	API      API
	Deployer *Deployer
	ID       *Identity
	Log      *slog.Logger
}

// needsDeploy is level-triggered on the assignment, never on-disk bytes: a
// grant redeploys when the version, the server's redeploy_seq (bumped by an
// explicit Redeploy or by server-side auto-remediation), or the rendered
// file list itself differs from what was last successfully written, or the
// last attempt for this grant failed (gs.Pending). An on-disk mismatch is
// not read here at all; it is reported through the heartbeat's installed
// digests, and the server marks it drift (with auto-remediate, that bumps
// redeploySeq, which is what actually forces the next redeploy here).
//
// versionID is uuid.UUID{} for a version-less assignment (a.VersionID nil,
// C3): GrantState.VersionID stores the same zero value then, so a later
// reconcile still redeploys the instant a real version arrives.
func needsDeploy(gs GrantState, versionID uuid.UUID, a agentproto.Assignment) bool {
	return gs.Pending || gs.VersionID != versionID || gs.RedeploySeq != a.RedeploySeq || !slices.Equal(gs.Files, a.Files)
}

func installedResult(a agentproto.Assignment) agentproto.GrantResult {
	res := agentproto.GrantResult{GrantID: a.ID, State: agentproto.StateOK, Installed: []agentproto.FileDigest{}}
	if a.VersionID != nil {
		res.VersionID = *a.VersionID
	}
	for _, f := range a.Files {
		sum, _, _ := fileDigest(f.Path)
		res.Installed = append(res.Installed, agentproto.FileDigest{Path: f.Path, SHA256: sum})
	}
	return res
}

func stale(old, current []agentproto.FileSpec) []agentproto.FileSpec {
	var out []agentproto.FileSpec
	for _, o := range old {
		if !slices.ContainsFunc(current, func(c agentproto.FileSpec) bool { return c.Path == o.Path }) {
			out = append(out, o)
		}
	}
	return out
}

// unclaimed drops files that a live assignment lists. The server never lets
// two grants share a path, but a removal and a new grant for the same path
// can meet in one reconcile; the live grant keeps the file.
func unclaimed(files []agentproto.FileSpec, live map[string]bool) []agentproto.FileSpec {
	out := make([]agentproto.FileSpec, 0, len(files))
	for _, f := range files {
		if !live[f.Path] {
			out = append(out, f)
		}
	}
	return out
}

// unclaimedPaths is unclaimed for a plain path list, as a server removal
// message carries.
func unclaimedPaths(paths []string, live map[string]bool) []agentproto.FileSpec {
	out := make([]agentproto.FileSpec, 0, len(paths))
	for _, p := range paths {
		if !live[p] {
			out = append(out, agentproto.FileSpec{Path: p})
		}
	}
	return out
}

// union appends to files every path in extra not already present in files,
// so a removal never relies on a single source of truth for what to delete:
// a partial write failure that left state.json out of step with what the
// server's removal message lists must still get every file removed.
func union(files, extra []agentproto.FileSpec) []agentproto.FileSpec {
	for _, e := range extra {
		if !slices.ContainsFunc(files, func(f agentproto.FileSpec) bool { return f.Path == e.Path }) {
			files = append(files, e)
		}
	}
	return files
}

// certsDirFromTarget recovers the certs/<name> directory for a removal whose
// grant left no local state at all (so there is no stored GrantState.CertsDir
// to prune by): only when the removal names its target and lists at least
// one file under that target's own certs/ prefix, read off that file's own
// path, never guessed from a fixed filename such as privkey.pem (a layout
// file may happen to be named that in a directory that is not a Traefik
// target's certs/<name> directory at all).
func certsDirFromTarget(t *agentproto.Target, files []string) string {
	if t == nil || t.Type != "traefik" {
		return ""
	}
	cfg, err := delivery.ParseTraefik(t.Config)
	if err != nil {
		return ""
	}
	prefix := filepath.Join(cfg.Dir, "certs") + string(filepath.Separator)
	for _, p := range files {
		if !strings.HasPrefix(p, prefix) {
			continue
		}
		if rest := strings.TrimPrefix(p, prefix); rest != "" {
			if i := strings.IndexRune(rest, filepath.Separator); i > 0 {
				return filepath.Join(cfg.Dir, "certs", rest[:i])
			}
		}
	}
	return ""
}

// recordDeployOutcome applies one grant's deploy result to state.json the
// same way whether it came from Deploy (a real version) or DeployTargetOnly
// (versionID zero, C3): on failure it only marks gs.Pending, keeping the
// last confirmed state so stale/orphan cleanup still finds those files; on
// success it removes files stale relative to written and saves the new
// GrantState.
func (r *Reconciler) recordDeployOutcome(st *State, live map[string]bool, a agentproto.Assignment, gs GrantState, had bool,
	versionID uuid.UUID, res agentproto.GrantResult, written []agentproto.FileSpec, certsDir string) {
	if res.State != agentproto.StateOK {
		// A failed deploy never overwrites this grant's last successfully
		// confirmed state; it is left exactly as it was, only marked
		// Pending, so stale/orphan cleanup can still find and remove those
		// old files once the assignment moves on, and so the next
		// reconcile retries regardless of whether version/redeploySeq/files
		// still match this stale state. A grant with no confirmed deploy
		// yet has nothing to keep.
		if had {
			gs.Pending = true
			st.Grants[a.ID] = gs
		}
		return
	}
	if len(written) == 0 {
		return
	}
	if had {
		stf := unclaimed(stale(gs.Files, written), live)
		if _, err := r.Deployer.Remove(stf, gs.CertsDir); err != nil {
			r.Log.Warn("old files not removed", "grant", a.ID, "err", err)
		}
	}
	st.Grants[a.ID] = GrantState{VersionID: versionID, RedeploySeq: a.RedeploySeq, CertificateName: a.CertificateName,
		Files: written, CertsDir: certsDir}
}

// Reconcile removes removed and orphaned grants' files first (never a path a
// live assignment lists), then deploys new or changed grants, reports every
// live grant (so the server always learns the current digests), and saves
// state.json.
func (r *Reconciler) Reconcile(ctx context.Context) (agentproto.Report, error) {
	as, err := r.API.Assignments(ctx)
	if err != nil {
		return agentproto.Report{}, err
	}
	st := &r.ID.State
	if st.Grants == nil {
		st.Grants = map[uuid.UUID]GrantState{}
	}
	rep := agentproto.Report{Revision: as.Revision, Results: []agentproto.GrantResult{}}
	known := map[uuid.UUID]bool{}
	live := map[string]bool{}
	for _, a := range as.Grants {
		known[a.ID] = true
		for _, f := range a.Files {
			live[f.Path] = true
		}
	}
	for _, rm := range as.Removed {
		known[rm.ID] = true
		gs, hadState := st.Grants[rm.ID]
		files := union(unclaimed(gs.Files, live), unclaimedPaths(rm.Files, live))
		certsDir := gs.CertsDir
		if !hadState {
			certsDir = certsDirFromTarget(rm.Target, rm.Files)
		}
		if _, err := r.Deployer.Remove(files, certsDir); err != nil {
			rep.Results = append(rep.Results, agentproto.GrantResult{GrantID: rm.ID, State: agentproto.StateFailed, Error: "remove: " + err.Error()})
			continue
		}
		delete(st.Grants, rm.ID)
		rep.Results = append(rep.Results, agentproto.GrantResult{GrantID: rm.ID, State: agentproto.StateOK, Installed: []agentproto.FileDigest{}})
	}
	for id, gs := range st.Grants {
		if known[id] {
			continue
		}
		files := unclaimed(gs.Files, live)
		if _, err := r.Deployer.Remove(files, gs.CertsDir); err != nil {
			rep.Results = append(rep.Results, agentproto.GrantResult{GrantID: id, State: agentproto.StateFailed, Error: "remove: " + err.Error()})
			r.Log.Warn("files of a grant the server no longer lists were not removed", "grant", id, "err", err)
			continue
		}
		delete(st.Grants, id)
	}
	for _, a := range as.Grants {
		gs, had := st.Grants[a.ID]
		var versionID uuid.UUID
		if a.VersionID != nil {
			versionID = *a.VersionID
		}
		if had && !needsDeploy(gs, versionID, a) {
			rep.Results = append(rep.Results, installedResult(a))
			continue
		}
		if a.VersionID == nil {
			// C3: a certificate with no version yet has no bundle to fetch
			// (Bundle 404s "no issued version yet" for it) — install the
			// target's material-independent files (the Traefik ACME router
			// file) straight from a.Target's config instead.
			res, written, certsDir := r.Deployer.DeployTargetOnly(a)
			r.recordDeployOutcome(st, live, a, gs, had, versionID, res, written, certsDir)
			rep.Results = append(rep.Results, res)
			continue
		}
		b, err := r.API.Bundle(ctx, a.ID)
		if err != nil {
			if had {
				gs.Pending = true
				st.Grants[a.ID] = gs
			}
			rep.Results = append(rep.Results, agentproto.GrantResult{GrantID: a.ID, VersionID: versionID,
				State: agentproto.StateFailed, Error: "bundle: " + err.Error()})
			continue
		}
		res, written, certsDir := r.Deployer.Deploy(ctx, a, b)
		r.recordDeployOutcome(st, live, a, gs, had, versionID, res, written, certsDir)
		rep.Results = append(rep.Results, res)
	}
	st.Revision = as.Revision
	return rep, r.ID.SaveState()
}
