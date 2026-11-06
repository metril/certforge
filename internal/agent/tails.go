package agent

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/actions"
	"github.com/metril/certforge/internal/agentproto"
)

// tailJob is a grant whose post_deploy tail awaits the run's merge: the
// batchable hook and everything after it. Its result and state.json update
// are finished once the tail ran.
type tailJob struct {
	a         agentproto.Assignment
	gs        GrantState
	had       bool
	versionID uuid.UUID
	written   []agentproto.FileSpec
	certsDir  string
	tail      []agentproto.HookSpec
	env       []string
	idx       int // the grant's index in the report's results
	failed    bool
}

var tailNS = uuid.MustParse("6f1c0e0e-5b53-4f43-9a7e-0a1a6c1d4a11")

// runTails merges the grants' tails (see actions.MergeTails) and runs each
// merged hook once: restarts are keyed by target, opted-in execs by action.
// A run is appended to every grant it ran for. A failing hook fails every
// grant it ran for and skips their later tail hooks; other grants go on.
func (r *Reconciler) runTails(ctx context.Context, jobs map[uuid.UUID]*tailJob, results []agentproto.GrantResult) {
	specs := map[uuid.UUID]agentproto.HookSpec{}
	tails := map[uuid.UUID][]actions.ActionRef{}
	for g, j := range jobs {
		for i, h := range j.tail {
			ref := actions.ActionRef{Kind: "exec"} // not batchable: unique per grant and position
			ref.ID = uuid.NewSHA1(tailNS, []byte(fmt.Sprintf("%s:%d", g, i)))
			switch {
			case h.Kind == "restart":
				ref.Kind, ref.ID = "restart", uuid.NewSHA1(tailNS, []byte("restart:"+h.Target))
			case h.OncePerHost:
				ref.Kind, ref.ID = "once", uuid.NewSHA1(tailNS, []byte("once:"+h.ID.String()))
			}
			if _, ok := specs[ref.ID]; !ok {
				specs[ref.ID] = h
			}
			tails[g] = append(tails[g], ref)
		}
	}
	isBatch := func(r actions.ActionRef) bool { return r.Kind != "exec" }
	for _, ms := range actions.MergeTails(tails, isBatch) {
		var live []uuid.UUID
		for _, g := range ms.Grants {
			if !jobs[g].failed {
				live = append(live, g)
			}
		}
		if len(live) == 0 {
			continue
		}
		h := specs[ms.Ref.ID]
		run := r.Deployer.runHook(ctx, h, jobs[live[0]].env)
		for _, g := range live {
			res := &results[jobs[g].idx]
			res.HookRuns = append(res.HookRuns, run)
			if run.ExitCode == 0 {
				continue
			}
			jobs[g].failed = true
			if res.State == agentproto.StateOK {
				res.State, res.Error = agentproto.StateFailed, fmt.Sprintf("post_deploy hook %s exited %d; the files are installed", hookName(h), run.ExitCode)
			}
		}
	}
}
