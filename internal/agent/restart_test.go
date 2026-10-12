//go:build unix

package agent

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
)

// dockerStub serves h on a unix socket and returns the socket path.
func dockerStub(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(h)
	srv.Listener = l
	srv.Start()
	t.Cleanup(srv.Close)
	return sock
}

func restartSpec(target string) agentproto.HookSpec {
	return agentproto.HookSpec{ID: uuid.New(), Phase: "post_deploy", Kind: "restart", Target: target, TimeoutSeconds: 2}
}

func TestRestartDocker(t *testing.T) {
	var gotPath, gotMethod string
	sock := dockerStub(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotMethod = r.URL.RequestURI(), r.Method
		switch {
		case strings.Contains(r.URL.Path, "/missing/"):
			http.Error(w, `{"message":"No such container"}`, 404)
		case strings.Contains(r.URL.Path, "/boom/"):
			http.Error(w, strings.Repeat("x", 5000), 500)
		case strings.Contains(r.URL.Path, "/slow/"):
			time.Sleep(3 * time.Second)
		default:
			w.WriteHeader(204)
		}
	})
	rr := &RestartRunner{Allow: map[string]bool{"docker:nginx": true, "docker:missing": true, "docker:boom": true, "docker:slow": true}, DockerSocket: sock}
	ctx := context.Background()

	run := rr.Run(ctx, restartSpec("docker:nginx"))
	if run.ExitCode != 0 || gotMethod != "POST" || gotPath != "/v1.41/containers/nginx/restart?t=10" ||
		len(run.Argv) != 2 || run.Argv[0] != "restart" || run.Argv[1] != "docker:nginx" || run.Stdout == "" {
		t.Fatalf("204: %+v %s %s", run, gotMethod, gotPath)
	}
	if run = rr.Run(ctx, restartSpec("docker:missing")); run.ExitCode != -1 || !strings.Contains(run.Stderr, "no such container") {
		t.Fatalf("404: %+v", run)
	}
	if run = rr.Run(ctx, restartSpec("docker:boom")); run.ExitCode != -1 || !strings.Contains(run.Stderr, "500") || len(run.Stderr) > 700 {
		t.Fatalf("500: len %d %+v", len(run.Stderr), run)
	}
	if run = rr.Run(ctx, restartSpec("docker:slow")); run.ExitCode != -1 || !strings.Contains(run.Stderr, "did not finish") {
		t.Fatalf("timeout: %+v", run)
	}
}

func TestRestartNotAllowedOrBad(t *testing.T) {
	rr := &RestartRunner{Allow: map[string]bool{"docker:nginx": true}, DockerSocket: "/nonexistent.sock"}
	if run := rr.Run(context.Background(), restartSpec("docker:other")); run.ExitCode != -1 || !strings.Contains(run.Stderr, "not listed in CF_RESTART_ALLOW") {
		t.Fatalf("%+v", run)
	}
	if run := (*RestartRunner)(nil).Run(context.Background(), restartSpec("docker:nginx")); run.ExitCode != -1 || !strings.Contains(run.Stderr, "CF_RESTART_ALLOW") {
		t.Fatalf("nil runner %+v", run)
	}
	rr.Allow["docker:a/b"] = true
	if run := rr.Run(context.Background(), restartSpec("docker:a/b")); run.ExitCode != -1 || !strings.Contains(run.Stderr, "bad restart target") {
		t.Fatalf("bad target %+v", run)
	}
	if run := rr.Run(context.Background(), restartSpec("docker:nginx")); run.ExitCode != -1 || !strings.Contains(run.Stderr, "docker") {
		t.Fatalf("no socket %+v", run)
	}
}

func TestRestartSystemd(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "args")
	fake := filepath.Join(dir, "systemctl")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\necho \"$@\" > "+out+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	rr := &RestartRunner{Allow: map[string]bool{"systemd:nginx.service": true}, Systemctl: fake}
	run := rr.Run(context.Background(), restartSpec("systemd:nginx.service"))
	b, _ := os.ReadFile(out)
	if run.ExitCode != 0 || strings.TrimSpace(string(b)) != "restart nginx.service" || run.Argv[0] != "restart" || run.Argv[1] != "systemd:nginx.service" {
		t.Fatalf("%+v args %q", run, b)
	}
}

func TestParseRestartAllow(t *testing.T) {
	m, err := ParseRestartAllow(" docker:nginx, systemd:a.service ,")
	if err != nil || len(m) != 2 || !m["docker:nginx"] || !m["systemd:a.service"] {
		t.Fatalf("%v %v", m, err)
	}
	if m, err = ParseRestartAllow(""); err != nil || len(m) != 0 {
		t.Fatalf("%v %v", m, err)
	}
	if _, err = ParseRestartAllow("nginx"); err == nil {
		t.Fatal("bare name accepted")
	}
}

func TestDeployRestartPostHook(t *testing.T) {
	dir := t.TempDir()
	hits := 0
	sock := dockerStub(t, func(w http.ResponseWriter, r *http.Request) { hits++; w.WriteHeader(204) })
	d := testDeployer([]string{dir})
	d.Restart = &RestartRunner{Allow: map[string]bool{"docker:web": true}, DockerSocket: sock}
	versionID := uuid.New()
	p := filepath.Join(dir, "web.pem")
	mk := func(target string) agentproto.Assignment {
		return agentproto.Assignment{ID: uuid.New(), CertificateName: "web", VersionID: &versionID,
			Hooks: []agentproto.HookSpec{restartSpec(target)}}
	}
	b := agentproto.Bundle{VersionID: versionID, Files: []agentproto.BundleFile{{Path: p, Mode: "0644", Content: []byte("PEM")}}}
	res, _, _ := d.Deploy(context.Background(), mk("docker:web"), b)
	if res.State != agentproto.StateOK || hits != 1 || len(res.HookRuns) != 1 || res.HookRuns[0].Argv[1] != "docker:web" {
		t.Fatalf("ok: %+v hits %d", res, hits)
	}
	// An unlisted target fails the grant but the files stay installed.
	res, _, _ = d.Deploy(context.Background(), mk("docker:other"), b)
	if res.State != agentproto.StateFailed || !strings.Contains(res.Error, "restart docker:other") || len(res.Installed) != 1 {
		t.Fatalf("unlisted: %+v", res)
	}
	// A pre_deploy restart failure aborts before files are written.
	_ = os.Remove(p)
	a := mk("docker:other")
	a.Hooks[0].Phase = "pre_deploy"
	res, written, _ := d.Deploy(context.Background(), a, b)
	if res.State != agentproto.StateFailed || len(written) != 0 {
		t.Fatalf("pre: %+v", res)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatal("file written despite failed pre_deploy restart")
	}
}
