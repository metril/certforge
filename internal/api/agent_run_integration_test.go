//go:build integration

package api

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/metril/certforge/internal/agent"
	"github.com/metril/certforge/internal/agenthub"
	"github.com/metril/certforge/internal/agents"
)

func waitUntil(ctx context.Context, t *testing.T, what string, cond func() bool) {
	t.Helper()
	for !cond() {
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %s", what)
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// The whole agent against the real agent router: enrol, deploy, tamper,
// auto-remediate, revoke.
func TestAgentRunEndToEnd(t *testing.T) {
	hub := agenthub.New(slog.Default())
	t.Cleanup(hub.Shutdown)
	e := newAgentEnv(t, func(d *Deps) { d.Hub = hub })
	e.svc.Hub = hub
	e.svc.Settings = agents.StaticSettings(agents.Settings{AgentURL: e.ts.URL, HeartbeatSeconds: 1}, "")
	en := e.newClient(t, "web-1")
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	runErr := make(chan error, 1)
	go func() {
		runErr <- agent.Run(ctx, agent.Config{DataDir: filepath.Join(dir, "data"), Token: en.Token, Version: "it",
			WriteAllow: []string{dir}}, slog.Default())
	}()
	waitUntil(ctx, t, "agent connected", func() bool { return hub.Connected(en.Client.ID) })
	certID, _ := e.currentCert(t, "web")
	out := filepath.Join(dir, "ssl", "web.pem")
	layout := e.layout(t, "pem", out)
	gid, err := e.svc.CreateGrant(e.as("operator"), e.org, en.Client.ID, agents.GrantInput{CertID: certID, Delivery: "push", LayoutID: &layout, AutoRemediate: true})
	if err != nil {
		t.Fatal(err)
	}
	waitUntil(ctx, t, "deployment ok", func() bool { return e.deploymentState(t, gid) == "ok" })
	want, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(out, []byte("tampered"), 0o644); err != nil {
		t.Fatal(err)
	}
	waitUntil(ctx, t, "file restored", func() bool {
		b, _ := os.ReadFile(out)
		return bytes.Equal(b, want)
	})
	waitUntil(ctx, t, "deployment ok again", func() bool { return e.deploymentState(t, gid) == "ok" })
	if e.auditCount(t, "deployment.drift") < 1 {
		t.Fatal("drift not audited")
	}
	if _, err := e.svc.RevokeClient(e.as("operator"), e.org, en.Client.ID); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-runErr:
		if !errors.Is(err, agent.ErrRevoked) {
			t.Fatalf("run ended with %v", err)
		}
	case <-ctx.Done():
		t.Fatal("agent kept running after revocation")
	}
}
