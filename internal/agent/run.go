package agent

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/targets"
)

// ErrRevoked stops the agent: the server refused this client.
var ErrRevoked = errors.New("agent: the server refused this agent (revoked or re-enrolled); enrol it again with a new token")

var (
	errReconnect = errors.New("agent: reconnecting")
	errRekey     = errors.New("agent: the socket's session is nearly out of messages; reconnecting for fresh keys")
)

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
			return EnrollWith(ctx, EnrollOptions{Log: log}, cfg.DataDir, tok, Facts(cfg.Version))
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
	// Roots replaces the operating system's roots for TLS to a proxy (nil:
	// the OS roots); for embedding and tests.
	Roots *x509.CertPool
}

// client builds a Client for the configured transport mode.
func (a *Agent) client() *Client {
	return NewClientWith(a.ID, ClientOptions{Mode: a.Cfg.Transport, Roots: a.Roots})
}

// NewTargetsRegistry builds the agent's deploy target registry: every
// built-in type internal/targets ships (traefik) — never vault-kv, which
// is server-run only and registers nowhere near the agent binary
// (TestAgentRegistryHasNoVaultKV, cmd/certforge/registry_test.go). NewAgent
// wires this into Deployer.Reg for production; a test builds its own
// smaller or larger registry instead where that matters.
func NewTargetsRegistry() *targets.Registry {
	reg := targets.NewRegistry()
	targets.RegisterBuiltins(reg)
	return reg
}

// NewAgent wires the production file writer, hook runner, deploy target
// registry and challenge server. AllowLoopback is always true for the
// agent's own outbound HTTPFactory (Deviations R2): an agent-side target
// already runs inside whatever network the agent itself reaches.
func NewAgent(cfg Config, log *slog.Logger, id *Identity) *Agent {
	files := NewFileWriter(log)
	return &Agent{Cfg: cfg, Log: log, ID: id, Now: time.Now,
		Deployer: &Deployer{Files: files, Hooks: &HookRunner{Allow: cfg.HookAllow}, Log: log, WriteAllow: cfg.WriteAllow,
			Reg: NewTargetsRegistry(), HTTP: targets.HTTPFactory{AllowLoopback: true}},
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
	if err := a.client().Renew(ctx); err != nil {
		if IsUnauthorized(err) {
			return ErrRevoked
		}
		return fmt.Errorf("renew: %w", err)
	}
	cert, _ := a.ID.current()
	a.Log.Info("agent certificate renewed", "not_after", cert.NotAfter)
	return nil
}

// reconcileRetry is the first pause before a failed reconcile is retried; it
// doubles up to five minutes. A var so tests can shorten it.
var reconcileRetry = 5 * time.Second

func (a *Agent) reconcile(ctx context.Context, api API) (agentproto.Report, error) {
	return (&Reconciler{API: api, Deployer: a.Deployer, ID: a.ID, Log: a.Log}).Reconcile(ctx)
}

// pullOnce renews when due, reconciles over REST, reports and sends one
// heartbeat: certforge-agent pull, and the pull schedule while no socket is up.
func (a *Agent) pullOnce(ctx context.Context) error {
	if err := a.renewIfDue(ctx); err != nil {
		return err
	}
	cl := a.client()
	rep, err := a.reconcile(ctx, cl)
	if err == nil {
		err = cl.Report(ctx, rep)
	}
	if err == nil {
		err = cl.Heartbeat(ctx, agentproto.Heartbeat{Installed: a.ID.Installed()})
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
	return NewAgent(cfg, log, id).Run(ctx)
}

// Run is the package-level Run for an agent that is already enrolled.
func (a *Agent) Run(ctx context.Context) error {
	cfg, log := a.Cfg, a.Log
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
		if errors.Is(err, errReconnect) || errors.Is(err, errRekey) {
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
	cl := a.client()
	// A signed refusal on the upgrade means revoked, like on REST; an
	// unsigned failure is the network or a proxy and is retried.
	ws, err := cl.Dial(ctx)
	if err != nil {
		if IsUnauthorized(err) {
			return ErrRevoked
		}
		return err
	}
	defer ws.CloseNow() //nolint:errcheck // best-effort cleanup; the session's own error is what matters
	rekey := make(chan struct{}, 1)
	ws.SetOnNearCap(func() {
		select {
		case rekey <- struct{}{}:
		default:
		}
	})
	// parent outlives the session: the reconcile worker runs on it, so a
	// dropped socket never cancels a deploy partway (hooks killed, state.json
	// unsaved); only agent shutdown does.
	parent := ctx
	ctx, cancel := context.WithCancel(ctx)
	var workers sync.WaitGroup
	// Cancel the session and wait for the reconcile worker, which finishes
	// any run in flight, before the deferred conn.CloseNow above runs, so it
	// never sends on a closed connection. A result that cannot be sent is
	// recovered by the next session, whose first reconcile reports every
	// grant again.
	defer func() { cancel(); workers.Wait() }()
	// github.com/coder/websocket allows concurrent writers, so send needs
	// no lock of its own.
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
	// Reconciles (file writes and hooks, up to minutes) run on one worker
	// so the loop below keeps answering challenges meanwhile. wake has room
	// for one pending request: it is the dirty flag, so requests arriving
	// during a run coalesce into exactly one follow-up and are never dropped.
	wake := make(chan struct{}, 1)
	reconcileAndReport := func() {
		select {
		case wake <- struct{}{}:
		default:
		}
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		var retry <-chan time.Time // set after a failure: try again, backing off
		delay := reconcileRetry
		for {
			select {
			case <-ctx.Done():
				return
			case <-wake:
				delay = reconcileRetry // a fresh request starts over
			case <-retry:
			}
			retry = nil
			rep, err := a.reconcile(parent, cl)
			if err != nil {
				a.Log.Warn("reconcile failed; retrying", "err", err, "in", delay)
				retry = time.After(delay)
				delay = min(delay*2, 5*time.Minute)
				continue
			}
			delay = reconcileRetry
			if err := send(agentproto.DeployResult{Report: rep}); err != nil {
				a.Log.Warn("deploy result not sent", "err", err)
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-rekey:
			// The session is nearly out of messages: dial again for fresh keys.
			return errRekey
		case err := <-readErr:
			// Close codes are not authenticated (a proxy can send any), so
			// they only explain a reconnect; revocation is the sealed
			// "revoked" message or a signed refusal of the next upgrade.
			switch websocket.CloseStatus(err) {
			case agentproto.CloseReplaced:
				return fmt.Errorf("another connection for this client took over: %w", err)
			case agentproto.CloseRekey:
				return errRekey
			}
			return err
		case m := <-msgs:
			switch v := m.(type) {
			case agentproto.Welcome:
				if v.HeartbeatSeconds > 0 {
					heartbeat.Reset(time.Duration(v.HeartbeatSeconds) * time.Second)
				}
				reconcileAndReport()
			case agentproto.Sync:
				reconcileAndReport()
			case agentproto.TrustBundleUpdate:
				a.applyTrustUpdate(v.Bundle)
				// A CA rotation: move to a certificate from the new CA now, so
				// the old CA can be retired without waiting for this one to
				// come due. The renewal also fetches, over signed REST, any CA
				// the message could not vouch for.
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
			if err := send(agentproto.Heartbeat{Installed: a.ID.Installed()}); err != nil {
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

// applyTrustUpdate applies a trust_bundle_update received inside the sealed
// channel. A CA may be added only if it chains to the current bundle (issued or
// cross-signed by a CA already trusted); an independent new root is ignored
// (with the rest of that message) and arrives through the signed REST renewal that follows. CAs are only
// ever dropped to a subset of what is trusted now. The bundle is kept when
// nothing in it can be vouched for.
func (a *Agent) applyTrustUpdate(bundle string) {
	_, pool := a.ID.current()
	now := a.Now()
	var keep []*x509.Certificate
	rest, rejected := []byte(bundle), 0
	for {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			rejected++
			continue
		}
		if _, err := c.Verify(x509.VerifyOptions{Roots: pool, CurrentTime: now, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
			rejected++
			continue
		}
		keep = append(keep, c)
	}
	if rejected > 0 {
		// Nothing from a partly unverifiable message is applied; the signed
		// renewal that follows returns the real bundle.
		a.Log.Warn("trust bundle update names CAs that do not chain to the current bundle; fetching the bundle over a signed request", "rejected", rejected)
		return
	}
	if len(keep) == 0 {
		return
	}
	var out []byte
	for _, c := range keep {
		out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})...)
	}
	if err := a.ID.SaveBundle(out); err != nil {
		a.Log.Error("trust bundle not saved", "err", err)
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
