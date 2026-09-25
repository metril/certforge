//go:build unix

package agent

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/metril/certforge/internal/agentproto"
)

func TestHookRunnerAllowlist(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	run := (&HookRunner{}).Run(context.Background(), agentproto.HookSpec{Argv: []string{"/bin/sh", "-c", "touch " + marker}, TimeoutSeconds: 5}, nil)
	if run.ExitCode != -1 || !strings.Contains(run.Stderr, "CF_HOOK_ALLOW") {
		t.Fatalf("run %+v", run)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("a hook outside the allowlist ran")
	}
}

func TestHookRunnerArgvWithoutShell(t *testing.T) {
	run := (&HookRunner{Allow: []string{"/bin/echo"}}).Run(context.Background(),
		agentproto.HookSpec{Argv: []string{"/bin/echo", "$HOME; rm -rf /"}, TimeoutSeconds: 5}, nil)
	if run.ExitCode != 0 || run.Stdout != "$HOME; rm -rf /\n" {
		t.Fatalf("run %+v", run)
	}
}

func TestHookRunnerEnvAndExitCode(t *testing.T) {
	run := (&HookRunner{Allow: []string{"/bin/sh"}}).Run(context.Background(),
		agentproto.HookSpec{Argv: []string{"/bin/sh", "-c", "echo $CF_GRANT_ID; exit 3"}, TimeoutSeconds: 5}, []string{"CF_GRANT_ID=g1"})
	if run.ExitCode != 3 || run.Stdout != "g1\n" {
		t.Fatalf("run %+v", run)
	}
}

func TestHookRunnerTimeoutKillsGroup(t *testing.T) {
	start := time.Now()
	run := (&HookRunner{Allow: []string{"/bin/sh"}}).Run(context.Background(),
		agentproto.HookSpec{Argv: []string{"/bin/sh", "-c", "sleep 30 & sleep 30"}, TimeoutSeconds: 1}, nil)
	if time.Since(start) > 10*time.Second || run.ExitCode != -1 || !strings.Contains(run.Stderr, "killed after 1s") {
		t.Fatalf("run %+v after %s", run, time.Since(start))
	}
}

// Review Focus: a hook never sees the agent's own process environment.
func TestHookRunnerMinimalEnv(t *testing.T) {
	t.Setenv("CF_AGENT_TOKEN", "top-secret")
	t.Setenv("CF_HOOK_ALLOW", "/bin/sh")
	t.Setenv("CF_WRITE_ALLOW", "/etc/ssl")
	run := (&HookRunner{Allow: []string{"/bin/sh"}}).Run(context.Background(),
		agentproto.HookSpec{Argv: []string{"/bin/sh", "-c", "echo \"$CF_AGENT_TOKEN|$CF_HOOK_ALLOW|$CF_WRITE_ALLOW|$PATH\""}, TimeoutSeconds: 5}, nil)
	if want := "|||" + os.Getenv("PATH") + "\n"; run.ExitCode != 0 || run.Stdout != want {
		t.Fatalf("run %+v, want stdout %q (empty CF_* vars, real PATH)", run, want)
	}
}

func TestHookRunnerCapsOutput(t *testing.T) {
	run := (&HookRunner{Allow: []string{"/bin/sh"}}).Run(context.Background(), agentproto.HookSpec{
		Argv: []string{"/bin/sh", "-c", "i=0; while [ $i -lt 2000 ]; do echo aaaaaaaaaaaaaaaaaaaa; i=$((i+1)); done"}, TimeoutSeconds: 10}, nil)
	if len(run.Stdout) > OutputCap || !strings.HasSuffix(run.Stdout, "[output truncated]") {
		t.Fatalf("stdout %d bytes", len(run.Stdout))
	}
}
