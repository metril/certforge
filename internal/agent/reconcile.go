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

func needsDeploy(gs GrantState, a agentproto.Assignment) bool {
	if gs.Failed || gs.VersionID != a.VersionID || !slices.Equal(gs.Files, a.Files) {
		return true
	}
	for _, f := range a.Files {
		if sum, _, err := fileDigest(f.Path); err != nil || sum != f.SHA256 {
			return true
		}
	}
	return false
}

func installedResult(a agentproto.Assignment) agentproto.GrantResult {
	res := agentproto.GrantResult{GrantID: a.ID, VersionID: a.VersionID, State: agentproto.StateOK, Installed: []agentproto.FileDigest{}}
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
	if t == nil {
		return ""
	}
	cfg, err := delivery.ParseTarget(t.Type, t.Config)
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
		if had && !needsDeploy(gs, a) {
			rep.Results = append(rep.Results, installedResult(a))
			continue
		}
		b, err := r.API.Bundle(ctx, a.ID)
		if err != nil {
			rep.Results = append(rep.Results, agentproto.GrantResult{GrantID: a.ID, VersionID: a.VersionID,
				State: agentproto.StateFailed, Error: "bundle: " + err.Error()})
			continue
		}
		res, written, certsDir := r.Deployer.Deploy(ctx, a, b)
		if len(written) > 0 {
			if had {
				stf := unclaimed(stale(gs.Files, written), live)
				if _, err := r.Deployer.Remove(stf, gs.CertsDir); err != nil {
					r.Log.Warn("old files not removed", "grant", a.ID, "err", err)
				}
			}
			st.Grants[a.ID] = GrantState{VersionID: a.VersionID, CertificateName: a.CertificateName, Files: written,
				CertsDir: certsDir, Failed: res.State != agentproto.StateOK}
		}
		rep.Results = append(rep.Results, res)
	}
	st.Revision = as.Revision
	return rep, r.ID.SaveState()
}
