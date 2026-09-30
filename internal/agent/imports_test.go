package agent

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// forbiddenAgentDeps are the packages certforge-agent must never import
// (Global Constraints): internal/notify (outbound delivery, templates, the
// DB-backed registry), internal/deploy, internal/vault, internal/db, and
// internal/targets/targetstest (test-only types that must never reach a
// product binary). internal/targets and internal/notify/httpx are fine —
// both are database-free.
var forbiddenAgentDeps = []string{
	"github.com/metril/certforge/internal/notify",
	"github.com/metril/certforge/internal/deploy",
	"github.com/metril/certforge/internal/vault",
	"github.com/metril/certforge/internal/db",
	"github.com/metril/certforge/internal/targets/targetstest",
}

// TestAgentImports guards the agent binary's dependency boundary with
// go list -deps, the same command a human would run to check it by hand.
func TestAgentImports(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "github.com/metril/certforge/cmd/certforge-agent")
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("go list -deps: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("go list -deps: %v", err)
	}
	deps := strings.Fields(string(out))
	have := make(map[string]bool, len(deps))
	for _, d := range deps {
		have[d] = true
	}
	for _, f := range forbiddenAgentDeps {
		if have[f] {
			t.Errorf("cmd/certforge-agent depends on %s", f)
		}
	}
}
