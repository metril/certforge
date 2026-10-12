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
	rr := &RestartRunner{Allow: map[string]bool{"docker:nginx": true, "docker:missing": true, "docker:boom": true, "docker:slow": true}, DockerAddr: sock}
	ctx := context.Background()

	run := rr.Run(ctx, restartSpec("docker:nginx"))
	if run.ExitCode != 0 || gotMethod != "POST" || gotPath != "/containers/nginx/restart?t=10" ||
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
	rr := &RestartRunner{Allow: map[string]bool{"docker:nginx": true}, DockerAddr: "/nonexistent.sock"}
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
	d.Restart = &RestartRunner{Allow: map[string]bool{"docker:web": true}, DockerAddr: sock}
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

func TestRestartTargets(t *testing.T) {
	sock := dockerStub(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/containers/json" {
			http.Error(w, "no", 404)
			return
		}
		_, _ = w.Write([]byte(`[{"Names":["/nginx"]},{"Names":["/redis","/app/alias"]},{"Names":[]},{"Names":["/bad name!"]}]`))
	})
	rr := &RestartRunner{Allow: map[string]bool{"docker:nginx": true, "docker:stopped": true, "systemd:x.service": true}, DockerAddr: sock}
	got := map[string]agentproto.RestartTarget{}
	for _, tg := range rr.Targets(context.Background()) {
		got[tg.Target] = tg
	}
	if len(got) != 4 {
		t.Fatalf("targets = %+v", got)
	}
	if g := got["docker:nginx"]; !g.Allowed || g.Running == nil || !*g.Running {
		t.Fatalf("nginx = %+v", g)
	}
	if g := got["docker:redis"]; g.Allowed || g.Running == nil || !*g.Running {
		t.Fatalf("redis = %+v", g)
	}
	if g := got["docker:stopped"]; !g.Allowed || g.Running == nil || *g.Running {
		t.Fatalf("stopped = %+v", g)
	}
	if g := got["systemd:x.service"]; !g.Allowed || g.Running != nil {
		t.Fatalf("systemd = %+v", g)
	}
	if _, ok := got["docker:alias"]; ok {
		t.Fatal("secondary names must be skipped")
	}
}

func TestRestartTargetsDockerDown(t *testing.T) {
	rr := &RestartRunner{Allow: map[string]bool{"docker:nginx": true}, DockerAddr: "/nonexistent.sock"}
	got := rr.Targets(context.Background())
	if len(got) != 1 || !got[0].Allowed || got[0].Running != nil {
		t.Fatalf("targets = %+v", got)
	}
	if (*RestartRunner)(nil).Targets(context.Background()) != nil {
		t.Fatal("nil runner has no targets")
	}
}

func TestRestartTargetsCap(t *testing.T) {
	sock := dockerStub(t, func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder
		b.WriteString("[")
		for i := 0; i < 300; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(`{"Names":["/c` + strings.Repeat("a", 1) + string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + `"]}`)
		}
		b.WriteString("]")
		_, _ = w.Write([]byte(b.String()))
	})
	rr := &RestartRunner{Allow: map[string]bool{"docker:keep": true}, DockerAddr: sock}
	got := rr.Targets(context.Background())
	if len(got) != maxRestartTargets || got[0].Target != "docker:keep" {
		t.Fatalf("len %d first %v", len(got), got[0])
	}
}

func TestRestartTCP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/containers/nginx/restart"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/containers/json"):
			_, _ = w.Write([]byte(`[{"Names":["/nginx"]}]`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	network, addr, err := ParseDockerHost("tcp://" + srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	rr := &RestartRunner{Allow: map[string]bool{"docker:nginx": true}, DockerNetwork: network, DockerAddr: addr}
	hr := rr.Run(context.Background(), agentproto.HookSpec{ID: uuid.New(), Phase: "post", Target: "docker:nginx"})
	if hr.ExitCode != 0 {
		t.Fatalf("restart over tcp: %+v", hr)
	}
	ts := rr.Targets(context.Background())
	if len(ts) != 1 || ts[0].Running == nil || !*ts[0].Running {
		t.Fatalf("targets over tcp: %+v", ts)
	}
}

func TestRestartUnixExplicit(t *testing.T) {
	sock := dockerStub(t, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })
	rr := &RestartRunner{Allow: map[string]bool{"docker:a": true}, DockerNetwork: "unix", DockerAddr: sock}
	if hr := rr.Run(context.Background(), agentproto.HookSpec{ID: uuid.New(), Phase: "post", Target: "docker:a"}); hr.ExitCode != 0 {
		t.Fatalf("%+v", hr)
	}
}

func TestParseDockerHost(t *testing.T) {
	ok := map[string][2]string{
		"":                        {"unix", "/var/run/docker.sock"},
		"unix:///run/d.sock":      {"unix", "/run/d.sock"},
		"tcp://socket-proxy:2375": {"tcp", "socket-proxy:2375"},
		"tcp://127.0.0.1:23750":   {"tcp", "127.0.0.1:23750"},
	}
	for in, want := range ok {
		n, a, err := ParseDockerHost(in)
		if err != nil || n != want[0] || a != want[1] {
			t.Errorf("%q: %q %q %v", in, n, a, err)
		}
	}
	for _, in := range []string{"http://x:1", "ssh://h", "tcp://nohost", "tcp://:2375", "unix://rel", "unix://", "bogus", "tcp://h:1/path"} {
		if _, _, err := ParseDockerHost(in); err == nil {
			t.Errorf("%q: want error", in)
		}
	}
	host := func(v string) func(string) string {
		return func(k string) string {
			if k == "DOCKER_HOST" {
				return v
			}
			return ""
		}
	}
	c, err := LoadConfig(host("tcp://socket-proxy:2375"), "dev")
	if err != nil || c.DockerNetwork != "tcp" || c.DockerAddr != "socket-proxy:2375" {
		t.Errorf("config: %+v %v", c, err)
	}
	if c, err = LoadConfig(host(""), "dev"); err != nil || c.DockerNetwork != "unix" || c.DockerAddr != "/var/run/docker.sock" {
		t.Errorf("default config: %+v %v", c, err)
	}
	if _, err := LoadConfig(host("ssh://h"), "dev"); err == nil {
		t.Error("ssh scheme accepted")
	}
}

func TestDockerPathNegotiation(t *testing.T) {
	for _, tc := range []struct{ name, hdr, want string }{
		{"versioned", "1.47", "/v1.47/containers/"},
		{"missing", "", "/containers/"},
		{"invalid", "../x", "/containers/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var restart, list string
			sock := dockerStub(t, func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/_ping":
					if tc.hdr != "" {
						w.Header().Set("Api-Version", tc.hdr)
					}
					_, _ = w.Write([]byte("OK"))
				case r.Method == "POST":
					restart = r.URL.RequestURI()
					w.WriteHeader(204)
				default:
					list = r.URL.RequestURI()
					_, _ = w.Write([]byte("[]"))
				}
			})
			rr := &RestartRunner{Allow: map[string]bool{"docker:nginx": true}, DockerAddr: sock}
			if run := rr.Run(context.Background(), restartSpec("docker:nginx")); run.ExitCode != 0 {
				t.Fatalf("run: %+v", run)
			}
			rr.Targets(context.Background())
			if restart != tc.want+"nginx/restart?t=10" || list != tc.want+"json" {
				t.Fatalf("paths: %q %q", restart, list)
			}
		})
	}
}
