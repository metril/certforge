package agent

import (
	"context"
	"log/slog"
	"path/filepath"
	"slices"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
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

// certsDirOf finds the certs/<name> directory a Traefik target's own two
// files (fullchain.pem, privkey.pem) always share, so Remove can prune it
// once empty; "" when files carries neither.
func certsDirOf(files []agentproto.FileSpec) string {
	for _, f := range files {
		if filepath.Base(f.Path) == "privkey.pem" || filepath.Base(f.Path) == "fullchain.pem" {
			return filepath.Dir(f.Path)
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
		files := st.Grants[rm.ID].Files
		if len(files) == 0 {
			files = unclaimedPaths(rm.Files, live)
		} else {
			files = unclaimed(files, live)
		}
		if _, err := r.Deployer.Remove(files, certsDirOf(files)); err != nil {
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
		if _, err := r.Deployer.Remove(files, certsDirOf(files)); err != nil {
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
		res, written, _ := r.Deployer.Deploy(ctx, a, b)
		if len(written) > 0 {
			if had {
				stf := unclaimed(stale(gs.Files, written), live)
				if _, err := r.Deployer.Remove(stf, certsDirOf(stf)); err != nil {
					r.Log.Warn("old files not removed", "grant", a.ID, "err", err)
				}
			}
			st.Grants[a.ID] = GrantState{VersionID: a.VersionID, CertificateName: a.CertificateName, Files: written,
				Failed: res.State != agentproto.StateOK}
		}
		rep.Results = append(rep.Results, res)
	}
	st.Revision = as.Revision
	return rep, r.ID.SaveState()
}
