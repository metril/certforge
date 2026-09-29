//go:build integration

package notify_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/notify"
)

// newSources builds a Sources against pool with a real settings.Store and
// the given river.Inserter fake.
func newSources(pool *pgxpool.Pool, ins notify.Inserter) *notify.Sources {
	return &notify.Sources{Q: sqlcgen.New(pool), Emitter: &notify.Emitter{Pool: pool, River: ins}, Settings: newSettingsStore(pool)}
}

func TestIssuedEventOnVersion(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})

	ca := insertCA(t, pool, org, "Pebble")
	certID := insertCert(t, pool, org, "example", "example.test", []string{"www.example.test"})
	notAfter := time.Now().Add(90 * 24 * time.Hour).UTC().Round(time.Second)
	versionID := insertVersion(t, pool, certID, notAfter, ca)

	ins := &fakeInserter{}
	s := newSources(pool, ins)
	s.OnVersion(ctx, certID, versionID)

	if got := eventCount(t, pool, "cert.issued"); got != 1 {
		t.Fatalf("cert.issued events = %d, want 1", got)
	}
	details := eventDetails(t, pool, "cert.issued:"+versionID.String())
	for _, want := range []string{`"serial"`, `"names"`, `example.test`, `www.example.test`, `"caName"`, `Pebble`, `"notAfter"`} {
		if !strings.Contains(details, want) {
			t.Errorf("details = %s, missing %s", details, want)
		}
	}
	if got := len(ins.channelIDs()); got != 1 {
		t.Fatalf("delivery jobs = %d, want 1", got)
	}

	// A second OnVersion for the same version is a dedupe no-op (the same
	// version can never notify twice).
	s.OnVersion(ctx, certID, versionID)
	if got := eventCount(t, pool, "cert.issued"); got != 1 {
		t.Fatalf("cert.issued events after duplicate = %d, want still 1", got)
	}
}

// TestFailureThresholdOncePerDay: failures 1-2 emit nothing (below
// threshold 3); the 3rd emits; a 4th failure the same UTC day is a no-op
// (already fired today); a failure the next day emits again.
func TestFailureThresholdOncePerDay(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})
	setNotifySettings(t, pool, 3, 0)

	certID := insertCert(t, pool, org, "example", "example.test", nil)
	cert := issuance.Certificate{ID: certID, OrgID: org, Name: "example", CommonName: "example.test"}
	fi := issuance.FailureInfo{Step: "order", Class: "acme", ProblemType: "urn:ietf:params:acme:error:unauthorized", Status: 403}

	now := time.Date(2026, 9, 29, 10, 0, 0, 0, time.UTC)
	s := newSources(pool, &fakeInserter{})
	s.Now = func() time.Time { return now }

	s.OnFailure(ctx, cert, 1, fi)
	s.OnFailure(ctx, cert, 2, fi)
	if got := eventCount(t, pool, "cert.renewal_failed"); got != 0 {
		t.Fatalf("events after failures 1-2 = %d, want 0", got)
	}

	s.OnFailure(ctx, cert, 3, fi)
	if got := eventCount(t, pool, "cert.renewal_failed"); got != 1 {
		t.Fatalf("events after failure 3 = %d, want 1", got)
	}

	s.OnFailure(ctx, cert, 4, fi)
	if got := eventCount(t, pool, "cert.renewal_failed"); got != 1 {
		t.Fatalf("events after failure 4 (same day) = %d, want still 1", got)
	}

	now = now.Add(24 * time.Hour)
	s.OnFailure(ctx, cert, 5, fi)
	if got := eventCount(t, pool, "cert.renewal_failed"); got != 2 {
		t.Fatalf("events after failure 5 (next day) = %d, want 2", got)
	}
}

// TestFailurePayloadHasNoURLOrHost: a cause carrying a CA URL and a
// resolver hostname must never reach the stored event row, the webhook
// payload (notify.Payload) or a rendered SMTP email — issuance.ClassifyFailure's
// FailureInfo is the only thing OnFailure ever reads from the failure.
func TestFailurePayloadHasNoURLOrHost(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	org := dbtest.Org(t, pool)
	insertChannel(t, pool, testChannel{orgID: org, name: "all-events"})
	setNotifySettings(t, pool, 1, 0)

	certID := insertCert(t, pool, org, "example", "example.test", nil)
	cert := issuance.Certificate{ID: certID, OrgID: org, Name: "example", CommonName: "example.test"}

	cause := fmt.Errorf("dial CA at https://acme.example/acme/order/123 via dns.internal: %w", errors.New("connection refused"))
	fi := issuance.ClassifyFailure("order", cause)

	s := newSources(pool, &fakeInserter{})
	s.OnFailure(ctx, cert, 1, fi)

	var kind, summary string
	var detailsRaw []byte
	if err := pool.QueryRow(ctx, "SELECT kind, summary, details FROM notification_events WHERE org_id = $1 AND kind = 'cert.renewal_failed'", org).
		Scan(&kind, &summary, &detailsRaw); err != nil {
		t.Fatal(err)
	}
	leaks := []string{"https://", "acme.example", "dns.internal"}
	for _, l := range leaks {
		if strings.Contains(string(detailsRaw), l) || strings.Contains(summary, l) {
			t.Fatalf("event row leaked %q: summary=%q details=%s", l, summary, detailsRaw)
		}
	}

	var details map[string]any
	if err := json.Unmarshal(detailsRaw, &details); err != nil {
		t.Fatal(err)
	}
	ev := notify.Event{Kind: kind, Summary: summary, Details: details, Severity: notify.SeverityOf(kind),
		Resource: notify.Resource{Type: "certificate", ID: certID.String(), Name: cert.Name}}

	payload := notify.Payload(ev, notify.Target{})
	for _, l := range leaks {
		if bytes.Contains(payload, []byte(l)) {
			t.Fatalf("webhook payload leaked %q: %s", l, payload)
		}
	}

	srv := startFakeSMTP(t, fakeSMTPOptions{})
	host, port := splitAddr(t, srv.Addr())
	n := notify.SMTP{Settings: func(context.Context) (notify.SMTPSettings, string, error) {
		return notify.SMTPSettings{Host: host, Port: port, From: "certforge@example.test", Security: "none", TimeoutSeconds: 5}, "", nil
	}}
	if err := n.Send(ctx, ev, notify.Target{}, map[string]any{"to": []any{"ops@example.test"}}, nil); err != nil {
		t.Fatalf("SMTP Send: %v", err)
	}
	msgs := srv.Messages()
	if len(msgs) != 1 {
		t.Fatalf("messages = %d, want 1", len(msgs))
	}
	for _, l := range leaks {
		if strings.Contains(msgs[0].Data, l) {
			t.Fatalf("rendered email leaked %q: %s", l, msgs[0].Data)
		}
	}
}
