package agent

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// forbiddenAgentDeps are the packages certforge-agent must never depend on
// (Global Constraints): internal/notify (outbound delivery, templates, the
// DB-backed registry — exact only, since internal/notify/httpx is fine,
// database-free, and used by internal/targets itself), internal/deploy,
// internal/vault, internal/db, and internal/targets/targetstest (test-only
// types that must never reach a product binary) — each of those four
// matched by prefix, so a subpackage (internal/db/sqlcgen, a future
// internal/vault/... etc.) is caught too, not just the exact path.
// internal/targets itself is fine — database-free.
var forbiddenAgentDeps = []string{
	"github.com/metril/certforge/internal/deploy",
	"github.com/metril/certforge/internal/vault",
	"github.com/metril/certforge/internal/db",
	"github.com/metril/certforge/internal/targets/targetstest",
}

// forbiddenAgentDepExact is matched exactly, never by prefix: unlike the
// four above, one of its own subpackages (internal/notify/httpx) is
// explicitly allowed.
const forbiddenAgentDepExact = "github.com/metril/certforge/internal/notify"

// TestAgentImports guards the agent binary's dependency boundary with
// go list -deps, the same command a human would run to check it by hand.
func TestAgentImports(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", "github.com/metril/certforge/cmd/certforge-agent")
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			t.Fatalf("go list -deps: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("go list -deps: %v", err)
	}
	deps := strings.Fields(string(out))
	for _, d := range deps {
		if d == forbiddenAgentDepExact {
			t.Errorf("cmd/certforge-agent depends on %s", d)
		}
		for _, f := range forbiddenAgentDeps {
			if d == f || strings.HasPrefix(d, f+"/") {
				t.Errorf("cmd/certforge-agent depends on %s", d)
			}
		}
	}
}
