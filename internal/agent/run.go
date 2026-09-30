package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"runtime"
	"time"

	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/targets"
)

// ErrRevoked stops the agent: the server refused this client.
var ErrRevoked = errors.New("agent: the server refused this agent (revoked or re-enrolled); enrol it again with a new token")

var errReconnect = errors.New("agent: reconnecting")

// Facts describe this host.
func Facts(version string) agentproto.Facts {
	h, _ := os.Hostname()
	return agentproto.Facts{Hostname: h, OS: runtime.GOOS, Arch: runtime.GOARCH, AgentVersion: version}
}

// tokenPollInterval is how often EnsureEnrolled looks for the token file.
var tokenPollInterval = 5 * time.Second

// EnsureEnrolled loads the identity, enrolling first when there is none or
// the configured token differs from the one enrolled with. With neither an
// identity nor a token it waits for CF_AGENT_TOKEN_FILE, polling every 5 s.
func EnsureEnrolled(ctx context.Context, cfg Config, log *slog.Logger) (*Identity, error) {
	for {
		tok, err := cfg.ResolveToken()
		if err != nil {
			return nil, err
		}
		id, err := LoadIdentity(cfg.DataDir)
		switch {
		case err == nil && (tok == "" || id.State.TokenHash == TokenHashHex(tok)):
			return id, nil
		case err != nil && !errors.Is(err, ErrNotEnrolled):
			return nil, err
		case tok != "":
			log.Info("enrolling", "data", cfg.DataDir)
			return Enroll(ctx, cfg.DataDir, tok, Facts(cfg.Version))
		}
		if cfg.TokenFile == "" {
			return nil, errors.New("not enrolled: set CF_AGENT_TOKEN or CF_AGENT_TOKEN_FILE, or run certforge-agent enroll --token <token>")
		}
		log.Info("waiting for an enrolment token", "file", cfg.TokenFile)
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(tokenPollInterval):
		}
	}
}

type backoff struct{ min, max, cur time.Duration }

// next doubles from min to max and returns 50-100% of it (jitter).
func (b *backoff) next() time.Duration {
	if b.cur < b.min {
		b.cur = b.min
	} else if b.cur *= 2; b.cur > b.max {
		b.cur = b.max
	}
	return time.Duration(float64(b.cur) * (0.5 + rand.Float64()/2)) //nolint:gosec // jitter only
}

func (b *backoff) reset() { b.cur = 0 }

// Agent is a running certforge-agent.
type Agent struct {
	Cfg       Config
	Log       *slog.Logger
	ID        *Identity
	Deployer  *Deployer
	Challenge *ChallengeServer
	Now       func() time.Time
}

// NewTargetsRegistry builds the agent's deploy target registry: every
// built-in type internal/targets ships (traefik) — never vault-kv, which
// is server-run only and registers nowhere near the agent binary
// (TestAgentRegistryHasNoVaultKV, cmd/certforge/registry_test.go). This is
// the same construction the agent constructor (NewAgent) will wire into
// Deployer.Reg once registry-driven agent execution lands (Task 6); until
// then nothing calls it but its own tests.
func NewTargetsRegistry() *targets.Registry {
	reg := targets.NewRegistry()
	targets.RegisterBuiltins(reg)
	return reg
}

// NewAgent wires the production file writer, hook runner and challenge
// server.
func NewAgent(cfg Config, log *slog.Logger, id *Identity) *Agent {
	files := NewFileWriter(log)
	return &Agent{Cfg: cfg, Log: log, ID: id, Now: time.Now,
		Deployer:  &Deployer{Files: files, Hooks: &HookRunner{Allow: cfg.HookAllow}, Log: log, WriteAllow: cfg.WriteAllow},
		Challenge: NewChallengeServer(cfg, files, log)}
}

// capabilities lists what this agent tells the server it can do: traefik
// always, hooks when CF_HOOK_ALLOW is set, and http-01/tls-alpn-01 when the
// matching challenge listener is configured.
func capabilities(cfg Config) []string {
	caps := []string{"traefik"}
	if len(cfg.HookAllow) > 0 {
		caps = append(caps, "hooks")
	}
	if cfg.HTTP01Listen != "" {
		caps = append(caps, "http-01")
	}
	if cfg.TLSALPNListen != "" {
		caps = append(caps, "tls-alpn-01")
	}
	return caps
}

// renewDue reads the live certificate through the identity's lock: it can
// change concurrently under a renewal or a trust-bundle update.
func (a *Agent) renewDue() bool {
	cert, _ := a.ID.current()
	return agentproto.RenewDue(cert.NotBefore, cert.NotAfter, a.Now())
}

func (a *Agent) renewIfDue(ctx context.Context) error {
	if !a.renewDue() {
		return nil
	}
	return a.renew(ctx)
}

// renew replaces the agent certificate and ca.pem now.
func (a *Agent) renew(ctx context.Context) error {
	if err := NewClient(a.ID).Renew(ctx); err != nil {
		if IsUnauthorized(err) {
			return ErrRevoked
		}
		return fmt.Errorf("renew: %w", err)
	}
	cert, _ := a.ID.current()
	a.Log.Info("agent certificate renewed", "not_after", cert.NotAfter)
	return nil
}

func (a *Agent) reconcile(ctx context.Context, api API) (agentproto.Report, error) {
	return (&Reconciler{API: api, Deployer: a.Deployer, ID: a.ID, Log: a.Log}).Reconcile(ctx)
}

// pullOnce renews when due, reconciles over REST, reports and sends one
// heartbeat: certforge-agent pull, and the pull schedule while no socket is up.
func (a *Agent) pullOnce(ctx context.Context) error {
	if err := a.renewIfDue(ctx); err != nil {
		return err
	}
	cl := NewClient(a.ID)
	rep, err := a.reconcile(ctx, cl)
	if err == nil {
		err = cl.Report(ctx, rep)
	}
	if err == nil {
		err = cl.Heartbeat(ctx, agentproto.Heartbeat{Installed: a.ID.State.Installed()})
	}
	if IsUnauthorized(err) {
		return ErrRevoked
	}
	if err != nil {
		return err
	}
	a.Log.Info("pull complete", "revision", rep.Revision, "grants", len(rep.Results))
	return nil
}

// Run keeps the agent connected until ctx ends (nil) or the server refuses
// it (ErrRevoked), reconnecting with jittered backoff from 1 s to 60 s. The
// pull ticker (CF_AGENT_PULL_INTERVAL) belongs to Run, not the socket: while
// connected the session reconciles on it, and while the socket is down (for
// example a proxy that refuses WebSocket upgrades) Run pulls over REST.
func Run(ctx context.Context, cfg Config, log *slog.Logger) error {
	id, err := EnsureEnrolled(ctx, cfg, log)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	a := NewAgent(cfg, log, id)
	if err := a.Challenge.Start(ctx); err != nil {
		return err
	}
	var pull <-chan time.Time
	if cfg.PullInterval > 0 {
		t := time.NewTicker(cfg.PullInterval)
		defer t.Stop()
		pull = t.C
	}
	bo := backoff{min: time.Second, max: time.Minute}
	for {
		start := time.Now()
		err := a.session(ctx, pull)
		if ctx.Err() != nil {
			return nil
		}
		if errors.Is(err, ErrRevoked) {
			return err
		}
		if time.Since(start) > time.Minute {
			bo.reset()
		}
		wait := bo.next()
		if errors.Is(err, errReconnect) {
			wait = 0
		}
		log.Warn("agent connection ended; reconnecting", "err", err, "in", wait.Round(time.Millisecond))
		timer := time.NewTimer(wait)
	waiting:
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil
			case <-pull:
				if err := a.pullOnce(ctx); errors.Is(err, ErrRevoked) {
					timer.Stop()
					return err
				} else if err != nil {
					log.Warn("pull without a connection failed", "err", err)
				}
			case <-timer.C:
				break waiting
			}
		}
	}
}

func (a *Agent) session(ctx context.Context, pull <-chan time.Time) error {
	if err := a.renewIfDue(ctx); err != nil {
		return err
	}
	cl := NewClient(a.ID)
	conn, err := cl.Dial(ctx)
	if err != nil {
		if IsUnauthorized(err) {
			return ErrRevoked
		}
		return err
	}
	defer conn.CloseNow() //nolint:errcheck // best-effort cleanup; the session's own error is what matters
	ws := agentproto.WS{C: conn}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	send := func(m agentproto.Message) error {
		b, err := agentproto.Marshal(m)
		if err != nil {
			return err
		}
		wctx, wcancel := context.WithTimeout(ctx, 30*time.Second)
		defer wcancel()
		return ws.WriteMsg(wctx, b)
	}
	f := Facts(a.Cfg.Version)
	if err := send(agentproto.Hello{AgentVersion: f.AgentVersion, Hostname: f.Hostname, OS: f.OS, Arch: f.Arch, Capabilities: capabilities(a.Cfg)}); err != nil {
		return err
	}
	msgs, readErr := make(chan agentproto.Message, 8), make(chan error, 1)
	go func() {
		for {
			b, err := ws.ReadMsg(ctx)
			if err != nil {
				readErr <- err
				return
			}
			m, err := agentproto.Unmarshal(b)
			if err != nil {
				a.Log.Warn("unreadable server message", "err", err)
				continue
			}
			select {
			case msgs <- m:
			case <-ctx.Done():
				return
			}
		}
	}()
	heartbeat := time.NewTicker(time.Minute)
	defer heartbeat.Stop()
	renew := time.NewTicker(time.Hour)
	defer renew.Stop()
	reconcileAndReport := func() {
		rep, err := a.reconcile(ctx, cl)
		if err != nil {
			a.Log.Warn("reconcile failed", "err", err)
			return
		}
		if err := send(agentproto.DeployResult{Report: rep}); err != nil {
			a.Log.Warn("deploy result not sent", "err", err)
		}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			switch websocket.CloseStatus(err) {
			case agentproto.CloseRevoked:
				return ErrRevoked
			case agentproto.CloseReplaced:
				return fmt.Errorf("another connection for this client took over: %w", err)
			}
			return err
		case m := <-msgs:
			switch v := m.(type) {
			case agentproto.HelloAck:
				if v.HeartbeatSeconds > 0 {
					heartbeat.Reset(time.Duration(v.HeartbeatSeconds) * time.Second)
				}
				reconcileAndReport()
			case agentproto.Sync:
				reconcileAndReport()
			case agentproto.TrustBundleUpdate:
				if err := a.ID.SaveBundle([]byte(v.Bundle)); err != nil {
					a.Log.Error("trust bundle not saved", "err", err)
					continue
				}
				// A CA rotation: move to a certificate from the new CA now, so
				// the old CA can be retired without waiting for this one to
				// come due.
				if err := a.renew(ctx); errors.Is(err, ErrRevoked) {
					return err
				} else if err != nil {
					a.Log.Warn("renewal after a trust bundle update failed; retrying when due", "err", err)
				}
				return errReconnect
			case agentproto.Revoked:
				return ErrRevoked
			case agentproto.ChallengePresent:
				if err := send(a.Challenge.Present(v)); err != nil {
					a.Log.Warn("challenge_ready not sent", "err", err)
				}
			case agentproto.ChallengeCleanup:
				a.Challenge.CleanUp(v)
			}
		case <-heartbeat.C:
			if err := send(agentproto.Heartbeat{Installed: a.ID.State.Installed()}); err != nil {
				return err
			}
		case <-renew.C:
			if a.renewDue() {
				return errReconnect
			}
		case <-pull:
			reconcileAndReport()
		}
	}
}

// Pull reconciles once over REST, reports, sends a heartbeat and returns.
func Pull(ctx context.Context, cfg Config, log *slog.Logger) error {
	id, err := EnsureEnrolled(ctx, cfg, log)
	if err != nil {
		return err
	}
	return NewAgent(cfg, log, id).pullOnce(ctx)
}
