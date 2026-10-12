package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
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
// the engine API over the Docker endpoint (DOCKER_HOST), or a systemd unit through systemctl (no
// shell). Only targets listed exactly in Allow run.
type RestartRunner struct {
	Allow         map[string]bool // CF_RESTART_ALLOW entries, e.g. "docker:nginx"
	DockerNetwork string          // "unix" (default) or "tcp"; from DOCKER_HOST
	DockerAddr    string          // socket path or host:port; default /var/run/docker.sock
	Systemctl     string          // default /usr/bin/systemctl
}

// ParseDockerHost parses DOCKER_HOST: unix:///abs/path or tcp://host:port.
// Empty means the default unix socket.
func ParseDockerHost(s string) (network, addr string, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "unix", defaultDockerSocket, nil
	}
	u, perr := url.Parse(s)
	if perr != nil {
		return "", "", fmt.Errorf("DOCKER_HOST: %q is not a valid URL", s)
	}
	switch u.Scheme {
	case "unix":
		if u.Host != "" || !strings.HasPrefix(u.Path, "/") || u.Path == "/" {
			return "", "", fmt.Errorf("DOCKER_HOST: %q must be unix:///absolute/path", s)
		}
		return "unix", u.Path, nil
	case "tcp":
		h, port, herr := net.SplitHostPort(u.Host)
		if herr != nil || h == "" || port == "" || (u.Path != "" && u.Path != "/") {
			return "", "", fmt.Errorf("DOCKER_HOST: %q must be tcp://host:port", s)
		}
		return "tcp", u.Host, nil
	}
	return "", "", fmt.Errorf("DOCKER_HOST: %q must use unix:// or tcp://", s)
}

// dockerClient builds an HTTP client that dials the configured Docker
// endpoint. The returned func closes its idle connections.
func (r *RestartRunner) dockerClient() (*http.Client, func()) {
	network, addr := r.DockerNetwork, r.DockerAddr
	if network == "" {
		network = "unix"
	}
	if addr == "" {
		addr = defaultDockerSocket
	}
	tr := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
	return &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, tr.CloseIdleConnections
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
	client, closeConns := r.dockerClient()
	defer closeConns()
	u := "http://docker/v1.41/containers/" + url.PathEscape(name) + "/restart?t=10"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, nil)
	if err != nil {
		return "", err
	}
	resp, err := client.Do(req)
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

const maxRestartTargets = 200

// Targets lists what this agent can restart: every allowlisted entry (sorted,
// first) and, when the Docker socket answers, each running container by its
// primary name. Docker errors are logged at debug and ignored. Systemd units
// are never enumerated. Browsing never widens Allow.
func (r *RestartRunner) Targets(ctx context.Context) []agentproto.RestartTarget {
	if r == nil || len(r.Allow) == 0 {
		return nil
	}
	allowed := make([]string, 0, len(r.Allow))
	for t := range r.Allow {
		allowed = append(allowed, t)
	}
	sort.Strings(allowed)
	running, err := r.dockerRunning(ctx)
	if err != nil {
		slog.Debug("restart targets: docker not listed", "err", err)
	}
	var out []agentproto.RestartTarget
	seen := map[string]bool{}
	for _, t := range allowed {
		tg := agentproto.RestartTarget{Target: t, Allowed: true}
		if err == nil && strings.HasPrefix(t, "docker:") {
			v := running[t]
			tg.Running = &v
		}
		seen[t] = true
		out = append(out, tg)
	}
	names := make([]string, 0, len(running))
	for t := range running {
		names = append(names, t)
	}
	sort.Strings(names)
	for _, t := range names {
		if !seen[t] {
			v := true
			out = append(out, agentproto.RestartTarget{Target: t, Running: &v})
		}
	}
	if len(out) > maxRestartTargets {
		out = out[:maxRestartTargets]
	}
	return out
}

// dockerRunning returns "docker:<name>" for each running container.
func (r *RestartRunner) dockerRunning(ctx context.Context) (map[string]bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client, closeConns := r.dockerClient()
	defer closeConns()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/v1.41/containers/json", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("docker returned %d", resp.StatusCode)
	}
	var list []struct {
		Names []string `json:"Names"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&list); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, c := range list {
		if len(c.Names) == 0 {
			continue
		}
		t := "docker:" + strings.TrimPrefix(c.Names[0], "/")
		if delivery.RestartTargetRE.MatchString(t) {
			out[t] = true
		}
	}
	return out, nil
}
