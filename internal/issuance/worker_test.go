package issuance

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/challenge"
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

// TestWorkerAgentModeRulesFailUntilRelay: a via-agent http-01 rule and a
// tls-alpn-01 rule both validate (RuleSpec.Validate passes), but buildRouter
// refuses them with the exact message the brief promises until Task 7 wires
// the agent relay.
func TestWorkerAgentModeRulesFailUntilRelay(t *testing.T) {
	clientID := uuid.New()
	for _, spec := range []challenge.RuleSpec{
		{Match: "*", Method: challenge.MethodHTTP01, Via: challenge.ViaAgent, ClientID: &clientID},
		{Match: "*", Method: challenge.MethodTLSALPN01, ClientID: &clientID},
	} {
		if err := spec.Validate(); err != nil {
			t.Fatalf("%+v: Validate() = %v, want it to pass at the rule-shape level", spec, err)
		}
		w := &IssueWorker{Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
		cert := Certificate{ID: uuid.New(), OrgID: uuid.New(), CommonName: "example.com", Rules: []challenge.RuleSpec{spec}}
		tl := NewTimeline(time.Now, nil)
		_, _, err := w.buildRouter(context.Background(), cert, Effective{}, CA{}, uuid.New(), tl)
		if err == nil || !strings.Contains(err.Error(), "agent challenge relay not configured") {
			t.Fatalf("%+v: buildRouter error = %v", spec, err)
		}
	}
}
