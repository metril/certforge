package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/metril/certforge/internal/agentproto"
)

// passthroughEnv are the system environment variables a hook inherits
// unchanged; everything else (in particular CF_AGENT_* and CF_HOOK_ALLOW,
// which a hook has no business seeing) is left out.
var passthroughEnv = []string{"PATH", "HOME", "LANG", "TZ"}

// minimalEnv builds a hook's base environment: a short passthrough list plus
// any LC_* locale variables, never the agent's own process environment.
func minimalEnv() []string {
	var out []string
	for _, k := range passthroughEnv {
		if v, ok := os.LookupEnv(k); ok {
			out = append(out, k+"="+v)
		}
	}
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LC_") {
			out = append(out, kv)
		}
	}
	return out
}

// OutputCap bounds each of a hook's stdout and stderr.
const OutputCap = 8 << 10

const truncMarker = "\n[output truncated]"

type capped struct {
	buf       bytes.Buffer
	truncated bool
}

func (c *capped) Write(p []byte) (int, error) {
	room := OutputCap - len(truncMarker) - c.buf.Len()
	if len(p) > room {
		if room > 0 {
			c.buf.Write(p[:room])
		}
		c.truncated = true
	} else {
		c.buf.Write(p)
	}
	return len(p), nil
}

func (c *capped) String() string {
	if c.truncated {
		return c.buf.String() + truncMarker
	}
	return c.buf.String()
}

// HookRunner runs hooks whose argv[0] is exactly an Allow entry, directly
// (never through a shell), in their own process group.
type HookRunner struct {
	Allow []string
}

// Run executes spec and always returns a result; ExitCode -1 means it did
// not run, failed to start, or was killed at the timeout.
func (h *HookRunner) Run(ctx context.Context, spec agentproto.HookSpec, env []string) agentproto.HookRun {
	run := agentproto.HookRun{HookID: spec.ID, Phase: spec.Phase, Argv: spec.Argv, ExitCode: -1}
	if len(spec.Argv) == 0 {
		run.Stderr = "hook not run: empty argv"
		return run
	}
	if !slices.Contains(h.Allow, spec.Argv[0]) {
		run.Stderr = fmt.Sprintf("hook not run: %s is not listed in CF_HOOK_ALLOW on this agent", spec.Argv[0])
		return run
	}
	timeout := time.Duration(spec.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Minute
	}
	var stdout, stderr capped
	cmd := exec.Command(spec.Argv[0], spec.Argv[1:]...) //nolint:gosec // argv[0] is allowlisted; no shell
	cmd.Env = append(minimalEnv(), env...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	// A descendant that left the process group (setsid) can hold the output
	// pipes after the hook exits or is killed; Wait gives up on them after
	// WaitDelay instead of stalling the reconcile loop.
	cmd.WaitDelay = 5 * time.Second
	setProcessGroup(cmd)
	start := time.Now()
	if err := cmd.Start(); err != nil {
		run.Stderr = err.Error()
		return run
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	var err error
	killed := ""
	select {
	case err = <-done:
	case <-timer.C:
		killProcessGroup(cmd)
		err = <-done
		killed = fmt.Sprintf("\n[certforge-agent: killed after %s]", timeout)
	case <-ctx.Done():
		killProcessGroup(cmd)
		err = <-done
		killed = "\n[certforge-agent: killed because the agent is stopping]"
	}
	run.DurationMS = time.Since(start).Milliseconds()
	run.Stdout, run.Stderr = stdout.String(), stderr.String()+killed
	var ee *exec.ExitError
	switch {
	case killed != "":
		run.ExitCode = -1
	case err == nil:
		run.ExitCode = 0
	case errors.As(err, &ee):
		run.ExitCode = ee.ExitCode()
	case errors.Is(err, exec.ErrWaitDelay):
		run.ExitCode = cmd.ProcessState.ExitCode()
		run.Stderr += "\n[certforge-agent: output cut off; a process the hook started kept it open]"
	default:
		run.Stderr += "\n" + err.Error()
	}
	return run
}
