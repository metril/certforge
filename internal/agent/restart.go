package agent

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
)

const (
	defaultDockerSocket = "/var/run/docker.sock"
	defaultSystemctl    = "/usr/bin/systemctl"
	restartBodyCap      = 512
)

// RestartRunner runs restart hooks: it restarts a Docker container through
// the engine API on a unix socket, or a systemd unit through systemctl (no
// shell). Only targets listed exactly in Allow run.
type RestartRunner struct {
	Allow        map[string]bool // CF_RESTART_ALLOW entries, e.g. "docker:nginx"
	DockerSocket string          // default /var/run/docker.sock
	Systemctl    string          // default /usr/bin/systemctl
}

// ParseRestartAllow parses CF_RESTART_ALLOW: comma-separated exact
// docker:<name> or systemd:<unit> entries.
func ParseRestartAllow(s string) (map[string]bool, error) {
	var out map[string]bool
	for _, e := range strings.Split(s, ",") {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if !delivery.RestartTargetRE.MatchString(e) {
			return nil, fmt.Errorf("CF_RESTART_ALLOW: %q must be docker:<container> or systemd:<unit>", e)
		}
		if out == nil {
			out = map[string]bool{}
		}
		out[e] = true
	}
	return out, nil
}

// Run restarts spec.Target and always returns a result; ExitCode -1 means it
// did not run, failed, or timed out.
func (r *RestartRunner) Run(ctx context.Context, spec agentproto.HookSpec) agentproto.HookRun {
	run := agentproto.HookRun{HookID: spec.ID, Phase: spec.Phase, Argv: []string{"restart", spec.Target}, ExitCode: -1}
	if r == nil || !r.Allow[spec.Target] {
		run.Stderr = fmt.Sprintf("hook not run: %s is not listed in CF_RESTART_ALLOW on this agent", spec.Target)
		return run
	}
	if !delivery.RestartTargetRE.MatchString(spec.Target) {
		run.Stderr = fmt.Sprintf("hook not run: bad restart target %q", spec.Target)
		return run
	}
	timeout := time.Duration(spec.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = time.Minute
	}
	kind, name, _ := strings.Cut(spec.Target, ":")
	start := time.Now()
	switch kind {
	case "docker":
		ctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		msg, err := r.dockerRestart(ctx, name)
		if err != nil {
			run.Stderr = err.Error()
			if ctx.Err() != nil {
				run.Stderr = fmt.Sprintf("restart of %s did not finish within %s: %v", spec.Target, timeout, err)
			}
		} else {
			run.ExitCode, run.Stdout = 0, msg
		}
		run.DurationMS = time.Since(start).Milliseconds()
	default: // systemd
		sc := r.Systemctl
		if sc == "" {
			sc = defaultSystemctl
		}
		hr := (&HookRunner{Allow: []string{sc}}).Run(ctx,
			agentproto.HookSpec{ID: spec.ID, Phase: spec.Phase, Argv: []string{sc, "restart", name}, TimeoutSeconds: spec.TimeoutSeconds}, nil)
		hr.Argv = run.Argv
		return hr
	}
	return run
}

func (r *RestartRunner) dockerRestart(ctx context.Context, name string) (string, error) {
	sock := r.DockerSocket
	if sock == "" {
		sock = defaultDockerSocket
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", sock)
	}}
	defer tr.CloseIdleConnections()
	u := "http://docker/v1.41/containers/" + url.PathEscape(name) + "/restart?t=10"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := (&http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return "", fmt.Errorf("docker: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, restartBodyCap))
	switch resp.StatusCode {
	case http.StatusNoContent:
		return "restarted container " + name, nil
	case http.StatusNotFound:
		return "", fmt.Errorf("no such container: %s", name)
	}
	return "", fmt.Errorf("docker returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
}
