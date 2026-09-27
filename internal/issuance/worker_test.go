package issuance

import (
	"context"
	"crypto/x509"
	"errors"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/signer"
)

// TestTruncatedStackCap is the Review Focus for the fix-round bound on the
// panic path: a full stack trace can run to tens of KiB (deep recursion, or
// many goroutines dumped by some runtimes) and would otherwise dominate a
// Timeline's own 64 KiB log cap on its own.
func TestTruncatedStackCap(t *testing.T) {
	s := truncatedStack()
	if len(s) > maxPanicStackBytes+64 {
		t.Fatalf("stack is %d bytes, want at most ~%d", len(s), maxPanicStackBytes)
	}
	// A real call stack always has at least a frame or two; the trace itself
	// should never be empty (a bug here would defeat the point of logging it).
	if !strings.Contains(string(s), "goroutine") {
		t.Fatalf("does not look like a stack trace: %q", s[:min(len(s), 200)])
	}
}

func TestTruncateBytesCapsAndMarks(t *testing.T) {
	big := strings.Repeat("a", maxPanicStackBytes*3)
	out := truncateBytes([]byte(big), maxPanicStackBytes)
	if len(out) > maxPanicStackBytes+32 {
		t.Fatalf("truncated = %d bytes, want at most ~%d", len(out), maxPanicStackBytes)
	}
	if !strings.HasSuffix(string(out), "[stack truncated]") {
		t.Fatalf("missing truncation marker: %q", out[len(out)-40:])
	}
	small := []byte("short")
	if got := truncateBytes(small, maxPanicStackBytes); string(got) != "short" {
		t.Fatalf("short input was modified: %q", got)
	}
}

type recordingListener struct{ got [][2]uuid.UUID }

func (r *recordingListener) OnVersion(_ context.Context, certID, versionID uuid.UUID) {
	r.got = append(r.got, [2]uuid.UUID{certID, versionID})
}

type panicListener struct{}

func (panicListener) OnVersion(context.Context, uuid.UUID, uuid.UUID) { panic("boom") }

func TestNotifyVersionCallsEveryListener(t *testing.T) {
	rec := &recordingListener{}
	w := &IssueWorker{Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Listeners: []VersionListener{panicListener{}, rec}}
	c, v := uuid.New(), uuid.New()
	w.notifyVersion(context.Background(), c, v)
	if len(rec.got) != 1 || rec.got[0] != [2]uuid.UUID{c, v} {
		t.Fatalf("got %v", rec.got)
	}
}

// TestWorkerHTTP01ServerRule: a certificate with a single http-01 (via
// server) rule builds a router whose ChallengeTypes is exactly ["http-01"],
// and Present on it makes the token readable from the worker's HTTPTokens
// store — the server-side http-01 wiring task-6-brief.md asks for.
func TestWorkerHTTP01ServerRule(t *testing.T) {
	tokens := challenge.NewHTTPTokens(time.Minute)
	w := &IssueWorker{HTTPTokens: tokens, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cert := Certificate{
		ID: uuid.New(), OrgID: uuid.New(), CommonName: "example.com",
		Rules: []challenge.RuleSpec{{Match: "*", Method: challenge.MethodHTTP01}},
	}
	tl := NewTimeline(time.Now, nil)
	router, _, err := w.buildRouter(context.Background(), cert, Effective{}, CA{}, uuid.New(), tl)
	if err != nil {
		t.Fatal(err)
	}
	if got := router.ChallengeTypes(); len(got) != 1 || got[0] != "http-01" {
		t.Fatalf("ChallengeTypes = %v, want [http-01]", got)
	}
	if err := router.Present("example.com", "tok1", "keyauth-1"); err != nil {
		t.Fatal(err)
	}
	if got, ok := tokens.Get("tok1"); !ok || got != "keyauth-1" {
		t.Fatalf("token not readable from HTTPTokens: %q, %v", got, ok)
	}
}

// fakeRelay is a minimal challenge.AgentRelay recording its last call.
type fakeRelay struct {
	orgID, clientID uuid.UUID
	method          challenge.Method
	webroot         string
	err             error
}

func (f *fakeRelay) Provider(_ context.Context, orgID, clientID uuid.UUID, m challenge.Method, webroot string) (challenge.ChallengeProvider, error) {
	f.orgID, f.clientID, f.method, f.webroot = orgID, clientID, m, webroot
	if f.err != nil {
		return nil, f.err
	}
	return fakeAgentProvider{t: m.Type()}, nil
}

type fakeAgentProvider struct{ t challenge.Type }

func (p fakeAgentProvider) Type() challenge.Type                                  { return p.t }
func (p fakeAgentProvider) Present(context.Context, string, string, string) error { return nil }
func (p fakeAgentProvider) CleanUp(context.Context, string, string, string) error { return nil }
func (p fakeAgentProvider) Timeout() (time.Duration, time.Duration)               { return time.Second, time.Second }

// TestWorkerAgentModeRulesNeedRelay: a via-agent http-01 rule and a
// tls-alpn-01 rule both validate (RuleSpec.Validate passes); buildRouter
// refuses them while Relay is nil, and calls Relay.Provider with the
// rule's org, client, method and webroot once one is wired up (Task 7).
func TestWorkerAgentModeRulesNeedRelay(t *testing.T) {
	clientID := uuid.New()
	specs := []challenge.RuleSpec{
		{Match: "*", Method: challenge.MethodHTTP01, Via: challenge.ViaAgent, ClientID: &clientID, Webroot: "/var/www/acme"},
		{Match: "*", Method: challenge.MethodTLSALPN01, ClientID: &clientID},
	}
	for _, spec := range specs {
		if err := spec.Validate(); err != nil {
			t.Fatalf("%+v: Validate() = %v, want it to pass at the rule-shape level", spec, err)
		}
		w := &IssueWorker{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		cert := Certificate{ID: uuid.New(), OrgID: uuid.New(), CommonName: "example.com", Rules: []challenge.RuleSpec{spec}}
		tl := NewTimeline(time.Now, nil)
		if _, _, err := w.buildRouter(context.Background(), cert, Effective{}, CA{}, uuid.New(), tl); err == nil ||
			!strings.Contains(err.Error(), "agent challenge relay is not configured") {
			t.Fatalf("%+v: nil Relay buildRouter error = %v", spec, err)
		}
	}
	for _, spec := range specs {
		relay := &fakeRelay{}
		w := &IssueWorker{Relay: relay, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		orgID := uuid.New()
		cert := Certificate{ID: uuid.New(), OrgID: orgID, CommonName: "example.com", Rules: []challenge.RuleSpec{spec}}
		tl := NewTimeline(time.Now, nil)
		router, _, err := w.buildRouter(context.Background(), cert, Effective{}, CA{}, uuid.New(), tl)
		if err != nil {
			t.Fatalf("%+v: buildRouter error = %v", spec, err)
		}
		if got := router.ChallengeTypes(); len(got) != 1 || got[0] != string(spec.Method.Type()) {
			t.Fatalf("%+v: ChallengeTypes = %v", spec, got)
		}
		if relay.orgID != orgID || relay.clientID != clientID || relay.method != spec.Method || relay.webroot != spec.Webroot {
			t.Fatalf("%+v: Relay.Provider called with org=%s client=%s method=%s webroot=%q",
				spec, relay.orgID, relay.clientID, relay.method, relay.webroot)
		}
	}
	// A relay rejection (client offline, capability gone since the rule was
	// written) is wrapped with the rule's match for the attempt log.
	spec := specs[1]
	relay := &fakeRelay{err: errors.New("client web-1 is offline or cannot serve challenges")}
	w := &IssueWorker{Relay: relay, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	cert := Certificate{ID: uuid.New(), OrgID: uuid.New(), CommonName: "example.com", Rules: []challenge.RuleSpec{spec}}
	tl := NewTimeline(time.Now, nil)
	_, _, err := w.buildRouter(context.Background(), cert, Effective{}, CA{}, uuid.New(), tl)
	if err == nil || !strings.Contains(err.Error(), `rule "*": client web-1 is offline`) {
		t.Fatalf("relay rejection not wrapped with the rule: %v", err)
	}
}

// caaTestSigner is a minimal signer.Signer for caaStep unit tests. It does
// not implement signer.DirectoryInfo (caaStep's caaCheck=false path returns
// before ever type-asserting sig, so this test never needs one); Issue
// fails the test outright since caaStep must never reach an order itself —
// see TestIssueCAAForbidsBeforeOrder (worker_integration_test.go) for the
// real proof that Issue is never called on the forbidding path, which
// requires driving the whole worker through a real Store.
type caaTestSigner struct{ t *testing.T }

func (s caaTestSigner) Kind() string { return "fake" }
func (s caaTestSigner) Issue(context.Context, signer.IssueRequest) (*signer.Issued, error) {
	s.t.Fatal("Issue must not be called")
	return nil, nil
}
func (caaTestSigner) Revoke(context.Context, *x509.Certificate, int) error { return nil }
func (caaTestSigner) RenewalInfo(context.Context, *x509.Certificate) (*signer.Window, error) {
	return nil, nil
}

// TestWorkerCAAStepDisabled: caaCheck=false records the "caa" step as
// skipped and never even looks at the signer.
func TestWorkerCAAStepDisabled(t *testing.T) {
	cert := Certificate{ID: uuid.New(), OrgID: uuid.New(), CommonName: "example.com"}
	w := &IssueWorker{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	tl := NewTimeline(time.Now, nil)

	if err := w.caaStep(context.Background(), tl, cert, CA{}, Effective{}, caaTestSigner{t: t}, IssuanceSettings{CAACheck: false}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	steps, _ := tl.Snapshot()
	if len(steps) != 1 || steps[0].Name != "caa" || steps[0].Status != challenge.StepSkipped {
		t.Fatalf("steps = %+v, want one skipped caa step", steps)
	}
}

// TestReplacesEligible: signer.IssueRequest.Replaces (Task 12, RFC 9773 §5)
// is only worth setting when useAri is on and the current version was
// actually issued by the very CA this attempt is going to — an imported or
// uploaded version, or one issued elsewhere, has nothing this CA would
// recognise as ReplacesCertID.
func TestReplacesEligible(t *testing.T) {
	ca := uuid.New()
	other := uuid.New()
	cases := []struct {
		name   string
		useAri bool
		v      certstore.Version
		want   bool
	}{
		{"issued, same CA, useAri", true, certstore.Version{Source: "issued", CAID: &ca}, true},
		{"useAri off", false, certstore.Version{Source: "issued", CAID: &ca}, false},
		{"imported", true, certstore.Version{Source: "imported", CAID: &ca}, false},
		{"uploaded", true, certstore.Version{Source: "uploaded", CAID: &ca}, false},
		{"different CA", true, certstore.Version{Source: "issued", CAID: &other}, false},
		{"no CA recorded", true, certstore.Version{Source: "issued"}, false},
	}
	for _, c := range cases {
		if got := replacesEligible(c.useAri, c.v, ca); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
