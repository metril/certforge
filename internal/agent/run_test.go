package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
)

func TestHelloCapabilities(t *testing.T) {
	if got := capabilities(Config{}); !slices.Equal(got, []string{"traefik"}) {
		t.Fatalf("defaults %v", got)
	}
	if got := capabilities(Config{HookAllow: []string{"/bin/sh"}}); !slices.Equal(got, []string{"traefik", "hooks"}) {
		t.Fatalf("hooks %v", got)
	}
	if got := capabilities(Config{HTTP01Listen: ":8080", TLSALPNListen: ":5001"}); !slices.Equal(got, []string{"traefik", "http-01", "tls-alpn-01"}) {
		t.Fatalf("challenge listeners %v", got)
	}
	if got := capabilities(Config{HookAllow: []string{"/bin/sh"}, HTTP01Listen: ":8080"}); !slices.Equal(got, []string{"traefik", "hooks", "http-01"}) {
		t.Fatalf("combined %v", got)
	}
}

func TestBackoffBounds(t *testing.T) {
	b := backoff{min: time.Second, max: time.Minute}
	if d := b.next(); d < 500*time.Millisecond || d > time.Second {
		t.Fatalf("first %s", d)
	}
	var d time.Duration
	for range 20 {
		d = b.next()
	}
	if d < 30*time.Second || d > time.Minute {
		t.Fatalf("capped %s", d)
	}
	b.reset()
	if d := b.next(); d > time.Second {
		t.Fatalf("after reset %s", d)
	}
}

func TestEnsureEnrolledWaitsForTokenFile(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	cfg := Config{DataDir: t.TempDir(), TokenFile: t.TempDir() + "/token"}
	if _, err := EnsureEnrolled(ctx, cfg, discard); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
	if _, err := EnsureEnrolled(context.Background(), Config{DataDir: t.TempDir()}, discard); err == nil {
		t.Fatal("no token and no token file accepted")
	}
}

func TestEnsureEnrolledPicksUpTokenFile(t *testing.T) {
	f := newFakeServer(t)
	defer func(d time.Duration) { tokenPollInterval = d }(tokenPollInterval)
	tokenPollInterval = 20 * time.Millisecond
	cfg := Config{DataDir: t.TempDir(), TokenFile: filepath.Join(t.TempDir(), "token")}
	tok := f.token(t)
	go func() {
		time.Sleep(100 * time.Millisecond)
		tmp := cfg.TokenFile + ".tmp"
		if err := os.WriteFile(tmp, []byte(tok), 0o600); err == nil {
			_ = os.Rename(tmp, cfg.TokenFile)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	id, err := EnsureEnrolled(ctx, cfg, discard)
	if err != nil || id.State.ClientID != f.clientID {
		t.Fatalf("enrolled %v err %v", id, err)
	}
}

func testAgent(t *testing.T, f *fakeServer) *Agent {
	t.Helper()
	id, err := Enroll(context.Background(), t.TempDir(), f.token(t), Facts("test"))
	if err != nil {
		t.Fatal(err)
	}
	return NewAgent(Config{DataDir: id.Dir, Version: "test"}, discard, id)
}

func TestPullReconcilesReportsAndHeartbeats(t *testing.T) {
	f := newFakeServer(t)
	if err := Pull(context.Background(), Config{DataDir: t.TempDir(), Token: f.token(t), Version: "test"}, discard); err != nil {
		t.Fatal(err)
	}
	f.with(func() {
		if len(f.reports) != 1 || f.reports[0].Revision != 7 || f.heartbeats != 1 {
			t.Fatalf("reports %+v heartbeats %d", f.reports, f.heartbeats)
		}
	})
}

func TestSessionTrustBundleUpdateRenewsAndReconnects(t *testing.T) {
	f := newFakeServer(t)
	a := testAgent(t, f)
	next, _, err := agentca.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bundle := string(agentca.BundlePEM([]*x509.Certificate{f.ca.Cert, next}))
	f.with(func() { f.bundle, f.onWS = bundle, sendAndWait(agentproto.TrustBundleUpdate{Bundle: bundle}) })
	serial := a.ID.Cert.SerialNumber
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.session(ctx, nil); !errors.Is(err, errReconnect) {
		t.Fatalf("session = %v", err)
	}
	saved, _ := os.ReadFile(filepath.Join(a.ID.Dir, caFile))
	var renewals int
	f.with(func() { renewals = f.renewals })
	if string(saved) != bundle || renewals != 1 || a.ID.Cert.SerialNumber.Cmp(serial) == 0 {
		t.Fatalf("bundle saved %v renewals %d", string(saved) == bundle, renewals)
	}
	f.with(func() { f.onWS = sendAndWait(agentproto.Revoked{}) })
	if err := a.session(ctx, nil); !errors.Is(err, ErrRevoked) {
		t.Fatalf("reconnect with the new pool = %v", err)
	}
	f.with(func() {
		if f.wsConns != 2 {
			t.Fatalf("connections %d", f.wsConns)
		}
	})
}

// TestSessionAnswersChallengeDuringReconcile: a reconcile stuck on the
// server must not delay challenge_ready, and Syncs arriving meanwhile
// collapse into exactly one follow-up run.
func TestSessionAnswersChallengeDuringReconcile(t *testing.T) {
	f := newFakeServer(t)
	a := testAgent(t, f)
	gate := make(chan struct{})
	f.with(func() { f.assignGate = gate })
	type outcome struct {
		ready   bool
		results int
		hits    int
	}
	done := make(chan outcome, 1)
	f.with(func() {
		f.onWS = func(ctx context.Context, c *websocket.Conn) {
			var out outcome
			defer func() { done <- out }()
			send := func(m agentproto.Message) {
				b, _ := agentproto.Marshal(m)
				_ = c.Write(ctx, websocket.MessageText, b)
			}
			send(agentproto.Sync{})
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				var hits int
				f.with(func() { hits = f.assignHits })
				if hits == 1 {
					break
				}
			}
			send(agentproto.Sync{})
			send(agentproto.Sync{})
			send(agentproto.ChallengePresent{Token: "tok", Method: "dns-01"})
			rctx, rcancel := context.WithTimeout(ctx, 3*time.Second)
			defer rcancel()
			for !out.ready {
				_, b, err := c.Read(rctx)
				if err != nil {
					return
				}
				if m, err := agentproto.Unmarshal(b); err == nil {
					_, out.ready = m.(agentproto.ChallengeReady)
				}
			}
			close(gate)
			qctx, qcancel := context.WithTimeout(ctx, 2*time.Second)
			defer qcancel()
			for {
				_, b, err := c.Read(qctx)
				if err != nil {
					break
				}
				if m, err := agentproto.Unmarshal(b); err == nil {
					if _, ok := m.(agentproto.DeployResult); ok {
						out.results++
					}
				}
			}
			f.with(func() { out.hits = f.assignHits })
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	go func() { _ = a.session(ctx, nil) }()
	select {
	case out := <-done:
		if !out.ready {
			t.Fatal("challenge_ready was not sent while a reconcile was running")
		}
		if out.hits != 2 || out.results != 2 {
			t.Fatalf("assignment fetches %d, deploy results %d, want 2 and 2 (one run plus one follow-up)", out.hits, out.results)
		}
	case <-ctx.Done():
		t.Fatal("timed out")
	}
}

// TestSessionDropMidReconcileLetsReconcileFinish: a socket dropping while a
// reconcile runs must not cancel it; the session waits, the reconcile
// completes and state.json is saved.
func TestSessionDropMidReconcileLetsReconcileFinish(t *testing.T) {
	f := newFakeServer(t)
	a := testAgent(t, f)
	gate := make(chan struct{})
	f.with(func() {
		f.assignGate = gate
		f.onWS = func(ctx context.Context, c *websocket.Conn) {
			b, _ := agentproto.Marshal(agentproto.Sync{})
			_ = c.Write(ctx, websocket.MessageText, b)
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
				var hits int
				f.with(func() { hits = f.assignHits })
				if hits == 1 {
					break
				}
			}
			_ = c.CloseNow() // the socket drops while the reconcile is blocked
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ended := make(chan error, 1)
	go func() { ended <- a.session(ctx, nil) }()
	select {
	case err := <-ended:
		t.Fatalf("session returned (%v) before its reconcile finished", err)
	case <-time.After(500 * time.Millisecond):
	}
	close(gate)
	select {
	case <-ended:
	case <-ctx.Done():
		t.Fatal("session did not return after the reconcile finished")
	}
	b, err := os.ReadFile(filepath.Join(a.ID.Dir, stateFile))
	if err != nil || !strings.Contains(string(b), `"revision": 7`) {
		t.Fatalf("state.json after a dropped session = %s (err %v), want revision 7", b, err)
	}
}

func TestSessionRenewsWhenDue(t *testing.T) {
	f := newFakeServer(t)
	a := testAgent(t, f)
	due := a.ID.Cert.NotAfter.Add(-time.Hour)
	a.Now = func() time.Time { return due }
	f.with(func() { f.onWS = sendAndWait(agentproto.Revoked{}) })
	serial := a.ID.Cert.SerialNumber
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.session(ctx, nil); !errors.Is(err, ErrRevoked) {
		t.Fatalf("session = %v", err)
	}
	var renewals int
	f.with(func() { renewals = f.renewals })
	if renewals != 1 || a.ID.Cert.SerialNumber.Cmp(serial) == 0 {
		t.Fatalf("renewals %d", renewals)
	}
}

func TestDialUnauthorizedIsRevoked(t *testing.T) {
	f := newFakeServer(t)
	a := testAgent(t, f)
	f.with(func() { f.wsStatus = http.StatusUnauthorized })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.session(ctx, nil); !errors.Is(err, ErrRevoked) {
		t.Fatalf("session = %v", err)
	}
	if err := Run(ctx, a.Cfg, discard); !errors.Is(err, ErrRevoked) {
		t.Fatalf("Run = %v", err)
	}
}

func TestRunPullsWithoutSocket(t *testing.T) {
	f := newFakeServer(t)
	a := testAgent(t, f)
	f.with(func() { f.wsStatus = http.StatusBadGateway }) // a proxy that refuses upgrades
	cfg := a.Cfg
	cfg.PullInterval = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	if err := Run(ctx, cfg, discard); err != nil {
		t.Fatal(err)
	}
	f.with(func() {
		if len(f.reports) == 0 || f.heartbeats == 0 {
			t.Fatalf("reports %d heartbeats %d while the socket was down", len(f.reports), f.heartbeats)
		}
	})
}
