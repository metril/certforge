//go:build integration

package agents

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/crypto/cryptotest"
)

// countingBox counts Open calls.
type countingBox struct {
	cryptotest.PrefixBox
	opens atomic.Int64
}

func (b *countingBox) Open(ctx context.Context, s []byte) ([]byte, error) {
	b.opens.Add(1)
	return b.PrefixBox.Open(ctx, s)
}

// enrollCSR returns a fresh CSR and the key behind it.
func enrollCSR(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "agent"}}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})), key
}

// tokenFor finds the stored token for a client created by CreateClient, the way
// the enrol handler does after the proof of possession verified.
func (f *syncFixture) tokenFor(t *testing.T, e Enrolment) EnrollToken {
	t.Helper()
	tok, err := f.svc.EnrollTokenByLookup(context.Background(), agentproto.LookupIDBytes(agentproto.TokenHash(e.Token)))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func kindOf(err error) Kind {
	var ae *Error
	if errors.As(err, &ae) {
		return ae.Kind
	}
	return 0
}

type enrolEnv struct {
	*syncFixture
	now     time.Time
	pending []PendingApproval
}

func newEnrolEnv(t *testing.T, st Settings) *enrolEnv {
	t.Helper()
	e := &enrolEnv{syncFixture: newSyncFixture(t), now: time.Now().UTC().Truncate(time.Second)}
	e.svc.Settings = StaticSettings(st, "https://cf.example.test")
	e.svc.Now = func() time.Time { return e.now }
	e.svc.OnPendingApproval = func(_ context.Context, p PendingApproval) { e.pending = append(e.pending, p) }
	return e
}

func (e *enrolEnv) submit(t *testing.T, name string) (Enrolment, agentproto.EnrollAccepted, string) {
	t.Helper()
	en, err := e.svc.CreateClient(context.Background(), e.org, name, nil)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := enrollCSR(t)
	acc, err := e.svc.SubmitEnrollment(context.Background(), e.tokenFor(t, en), csr, agentproto.Facts{Hostname: name + ".lan", OS: "linux", Arch: "amd64", AgentVersion: "t"}, "10.0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	return en, acc, csr
}

func (e *enrolEnv) clientStatus(t *testing.T, id uuid.UUID) string {
	t.Helper()
	c, err := e.q.GetClientByID(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return c.Status
}

// A token redeemed with approval on creates a pending request, notifies once,
// issues nothing until approved, and the poll secret alone is not enough.
func TestEnrollmentPendingApproveCollect(t *testing.T) {
	e := newEnrolEnv(t, Settings{})
	ctx := context.Background()
	en, acc, csr := e.submit(t, "web-1")
	if acc.Status != agentproto.EnrollPending || len(acc.VerifyCode) != 8 || acc.PollSecret == "" || !acc.ExpiresAt.Equal(e.now.Add(24*time.Hour)) {
		t.Fatalf("accepted %+v", acc)
	}
	parsed, _ := agentca.ParseCSR([]byte(csr))
	oldest, _ := e.svc.CA.Oldest(ctx)
	if want := agentproto.VerifyCode(parsed.RawSubjectPublicKeyInfo, agentca.Fingerprint(oldest.Cert.Raw)); acc.VerifyCode != want {
		t.Fatalf("verify code %s, want %s", acc.VerifyCode, want)
	}
	if len(e.pending) != 1 || e.pending[0].VerifyCode != acc.VerifyCode || e.pending[0].ClientID != en.Client.ID || e.pending[0].Hostname != "web-1.lan" {
		t.Fatalf("pending events %+v", e.pending)
	}
	list, err := e.svc.ListPendingEnrollments(ctx, []uuid.UUID{e.org})
	if err != nil || len(list) != 1 || list[0].ID != acc.ID || list[0].ClientName != "web-1" || list[0].Facts.Hostname != "web-1.lan" || list[0].SourceIP != "10.0.0.9" {
		t.Fatalf("list %+v %v", list, err)
	}
	if res, err := e.svc.PollEnrollment(ctx, acc.ID, acc.PollSecret); err != nil || res.Status != agentproto.EnrollPending || res.Certificate != "" {
		t.Fatalf("poll before approval %+v %v", res, err)
	}
	if _, err := e.svc.PollEnrollment(ctx, acc.ID, "wrong"); kindOf(err) != KindUnauthorized {
		t.Fatalf("wrong secret: %v", err)
	}
	if e.clientStatus(t, en.Client.ID) != "pending" {
		t.Fatal("client active before approval")
	}

	if err := e.svc.ApproveEnrollment(ctx, e.org, acc.ID); err != nil {
		t.Fatal(err)
	}
	res, err := e.svc.PollEnrollment(ctx, acc.ID, acc.PollSecret)
	if err != nil || res.Status != agentproto.EnrollApproved || res.Certificate == "" || res.TrustBundle == "" || res.ClientID != en.Client.ID {
		t.Fatalf("poll after approval %+v %v", res, err)
	}
	if e.clientStatus(t, en.Client.ID) != "active" {
		t.Fatal("client not active after collection")
	}
	again, err := e.svc.PollEnrollment(ctx, acc.ID, acc.PollSecret)
	if err != nil || again.Certificate != res.Certificate {
		t.Fatalf("re-poll must repeat the same certificate: %v", err)
	}
	if list, _ := e.svc.ListPendingEnrollments(ctx, []uuid.UUID{e.org}); len(list) != 0 {
		t.Fatal("decided request still listed")
	}
	if err := e.svc.ApproveEnrollment(ctx, e.org, acc.ID); kindOf(err) != KindConflict {
		t.Fatalf("second approval: %v", err)
	}
}

func TestEnrollmentReject(t *testing.T) {
	e := newEnrolEnv(t, Settings{})
	ctx := context.Background()
	en, acc, _ := e.submit(t, "web-1")
	if err := e.svc.RejectEnrollment(ctx, uuid.New(), acc.ID); kindOf(err) != KindConflict && kindOf(err) != KindNotFound {
		t.Fatalf("other org: %v", err)
	}
	if err := e.svc.RejectEnrollment(ctx, e.org, acc.ID); err != nil {
		t.Fatal(err)
	}
	if res, err := e.svc.PollEnrollment(ctx, acc.ID, acc.PollSecret); err != nil || res.Status != agentproto.EnrollRejected || res.Certificate != "" {
		t.Fatalf("poll after rejection %+v %v", res, err)
	}
	if err := e.svc.ApproveEnrollment(ctx, e.org, acc.ID); kindOf(err) != KindConflict {
		t.Fatalf("approve after reject: %v", err)
	}
	if e.clientStatus(t, en.Client.ID) != "pending" {
		t.Fatal("rejection must leave the client pending")
	}
	if err := e.svc.ApproveEnrollment(ctx, e.org, uuid.New()); kindOf(err) != KindNotFound {
		t.Fatalf("unknown request: %v", err)
	}
	// The token stays used; re-enrolling the client clears the old request.
	csr, _ := enrollCSR(t)
	if _, err := e.svc.SubmitEnrollment(ctx, e.tokenFor(t, en), csr, agentproto.Facts{}, ""); kindOf(err) != KindUnauthorized {
		t.Fatalf("reused token: %v", err)
	}
	if _, err := e.svc.ReenrollClient(ctx, e.org, en.Client.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.PollEnrollment(ctx, acc.ID, acc.PollSecret); kindOf(err) != KindUnauthorized {
		t.Fatalf("poll of a cleared request: %v", err)
	}
}

func TestEnrollmentExpiry(t *testing.T) {
	e := newEnrolEnv(t, Settings{PendingTTLHours: 2})
	ctx := context.Background()
	_, acc, _ := e.submit(t, "web-1")
	if !acc.ExpiresAt.Equal(e.now.Add(2 * time.Hour)) {
		t.Fatalf("expires %v", acc.ExpiresAt)
	}
	e.now = e.now.Add(2*time.Hour + time.Second)
	if list, _ := e.svc.ListPendingEnrollments(ctx, []uuid.UUID{e.org}); len(list) != 0 {
		t.Fatal("expired request listed")
	}
	if err := e.svc.ApproveEnrollment(ctx, e.org, acc.ID); kindOf(err) != KindConflict {
		t.Fatalf("approve after expiry: %v", err)
	}
	if res, err := e.svc.PollEnrollment(ctx, acc.ID, acc.PollSecret); err != nil || res.Status != agentproto.EnrollExpired {
		t.Fatalf("poll after expiry %+v %v", res, err)
	}

	// An approved request must be collected within the same window.
	_, acc2, _ := e.submit(t, "web-2")
	if err := e.svc.ApproveEnrollment(ctx, e.org, acc2.ID); err != nil {
		t.Fatal(err)
	}
	e.now = e.now.Add(2*time.Hour + time.Second)
	if res, err := e.svc.PollEnrollment(ctx, acc2.ID, acc2.PollSecret); err != nil || res.Status != agentproto.EnrollExpired || res.Certificate != "" {
		t.Fatalf("collect after the window %+v %v", res, err)
	}
}

func TestEnrollmentPendingCap(t *testing.T) {
	e := newEnrolEnv(t, Settings{})
	ctx := context.Background()
	for i := range MaxPendingEnrollments {
		e.submit(t, fmt.Sprintf("web-%d", i))
	}
	en, err := e.svc.CreateClient(ctx, e.org, "one-too-many", nil)
	if err != nil {
		t.Fatal(err)
	}
	csr, _ := enrollCSR(t)
	if _, err := e.svc.SubmitEnrollment(ctx, e.tokenFor(t, en), csr, agentproto.Facts{}, ""); kindOf(err) != KindConflict {
		t.Fatalf("over the cap: %v", err)
	}
	var used int
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM enrollment_tokens WHERE client_id = $1 AND used_at IS NOT NULL`, en.Client.ID).Scan(&used); err != nil || used != 0 {
		t.Fatalf("a refused submission consumed the token (%d, %v)", used, err)
	}
	// Deciding one frees a slot.
	list, _ := e.svc.ListPendingEnrollments(ctx, []uuid.UUID{e.org})
	if err := e.svc.RejectEnrollment(ctx, e.org, list[0].ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SubmitEnrollment(ctx, e.tokenFor(t, en), csr, agentproto.Facts{}, ""); err != nil {
		t.Fatalf("after freeing a slot: %v", err)
	}
}

func TestEnrollmentApprovalOff(t *testing.T) {
	off := false
	e := newEnrolEnv(t, Settings{RequireApproval: &off})
	ctx := context.Background()
	en, acc, _ := e.submit(t, "web-1")
	if acc.Status != agentproto.EnrollApproved || len(e.pending) != 0 {
		t.Fatalf("accepted %+v pending events %d", acc, len(e.pending))
	}
	res, err := e.svc.PollEnrollment(ctx, acc.ID, acc.PollSecret)
	if err != nil || res.Certificate == "" || e.clientStatus(t, en.Client.ID) != "active" {
		t.Fatalf("poll %+v %v", res, err)
	}
	if !Resolve(Settings{}, "").ApprovalRequired() {
		t.Fatal("approval must default to required")
	}
}

// The same key may redeem the request again (a lost reply) and gets a new poll
// secret; another key may not, and the old secret stops working.
func TestEnrollmentResubmit(t *testing.T) {
	e := newEnrolEnv(t, Settings{})
	ctx := context.Background()
	en, acc, csr := e.submit(t, "web-1")
	again, err := e.svc.SubmitEnrollment(ctx, e.tokenFor(t, en), csr, agentproto.Facts{}, "")
	if err != nil || again.ID != acc.ID || again.PollSecret == acc.PollSecret || again.VerifyCode != acc.VerifyCode {
		t.Fatalf("resubmit %+v %v", again, err)
	}
	if _, err := e.svc.PollEnrollment(ctx, acc.ID, acc.PollSecret); kindOf(err) != KindUnauthorized {
		t.Fatalf("old poll secret after resubmission: %v", err)
	}
	if _, err := e.svc.PollEnrollment(ctx, acc.ID, again.PollSecret); err != nil {
		t.Fatal(err)
	}
	other, _ := enrollCSR(t)
	if _, err := e.svc.SubmitEnrollment(ctx, e.tokenFor(t, en), other, agentproto.Facts{}, ""); kindOf(err) != KindUnauthorized {
		t.Fatalf("a different key on a used token: %v", err)
	}
	if len(e.pending) != 1 {
		t.Fatalf("resubmission must not re-notify: %d events", len(e.pending))
	}
}

func TestEnrollmentUnknownTokenAndRevokedClient(t *testing.T) {
	e := newEnrolEnv(t, Settings{})
	ctx := context.Background()
	if _, err := e.svc.EnrollTokenByLookup(ctx, agentproto.LookupIDBytes(agentproto.TokenHash("cf1.unknown"))); kindOf(err) != KindUnauthorized {
		t.Fatalf("unknown token: %v", err)
	}
	en, err := e.svc.CreateClient(ctx, e.org, "web-1", nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := e.tokenFor(t, en)
	if _, err := e.pool.Exec(ctx, `UPDATE clients SET status = 'revoked' WHERE id = $1`, en.Client.ID); err != nil {
		t.Fatal(err)
	}
	csr, _ := enrollCSR(t)
	if _, err := e.svc.SubmitEnrollment(ctx, tok, csr, agentproto.Facts{}, ""); kindOf(err) != KindConflict {
		t.Fatalf("revoked client: %v", err)
	}
	var used int
	if err := e.pool.QueryRow(ctx, `SELECT count(*) FROM enrollment_tokens WHERE client_id = $1 AND used_at IS NOT NULL`, en.Client.ID).Scan(&used); err != nil || used != 0 {
		t.Fatal("a failed submission left its token consumed")
	}
	if _, err := e.pool.Exec(ctx, `UPDATE enrollment_tokens SET expires_at = now() - interval '1 minute' WHERE client_id = $1`, en.Client.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.pool.Exec(ctx, `UPDATE clients SET status = 'pending' WHERE id = $1`, en.Client.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := e.svc.SubmitEnrollment(ctx, tok, csr, agentproto.Facts{}, ""); kindOf(err) != KindUnauthorized {
		t.Fatalf("expired token: %v", err)
	}
}
