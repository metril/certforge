package issuance

import (
	"context"
	"crypto/x509"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/signer"
)

// ariPollBatch bounds how many certificates one ARIPollWorker run considers.
const ariPollBatch = 500

// ariDefaultRetryAfter spaces out the next poll when the CA's RenewalInfo
// response carries no Retry-After of its own.
const ariDefaultRetryAfter = 6 * time.Hour

// ARIPollArgs is the periodic job that polls every due certificate's ACME
// Renewal Information window (see ARIPollWorker).
type ARIPollArgs struct{}

// Kind implements river.JobArgs.
func (ARIPollArgs) Kind() string { return "certforge_ari_poll" }

// ARIPollWorker fetches the ACME Renewal Information window for every
// certificate due for one (Store.ARIDueCertificates) and, when it is
// earlier than the certificate's renewal-policy date, lowers
// next_renew_at into it — renewal only ever moves earlier. It is also
// called directly (pollOne) right after a successful issuance
// (IssueWorker.succeed), best-effort.
type ARIPollWorker struct {
	river.WorkerDefaults[ARIPollArgs]
	Store     *Store
	Certs     *certstore.Store
	NewSigner func(CA) signer.Signer
	Now       func() time.Time
	Rand      func() float64
	Log       *slog.Logger
}

// NewARIPollWorker wires production defaults. NewSigner never sets
// Config.Account: RenewalInfo is an unauthenticated GET (RFC 9773), so the
// poll never needs to load or decrypt an ACME account key.
func NewARIPollWorker(store *Store, certs *certstore.Store) *ARIPollWorker {
	return &ARIPollWorker{Store: store, Certs: certs, NewSigner: DefaultSigner, Now: time.Now, Rand: rand.Float64, Log: slog.Default()}
}

func (w *ARIPollWorker) logger() *slog.Logger {
	if w.Log != nil {
		return w.Log
	}
	return slog.Default()
}

// Work implements river.Worker.
func (w *ARIPollWorker) Work(ctx context.Context, _ *river.Job[ARIPollArgs]) error {
	return w.PollDue(ctx, ariPollBatch)
}

// PollDue polls up to limit due certificates. One certificate's error is
// logged and does not stop the rest of the batch, or fail the job (the
// most common cause — a CA directory that does not publish a renewalInfo
// endpoint at all — would otherwise repeat for every certificate on that
// CA on every run).
func (w *ARIPollWorker) PollDue(ctx context.Context, limit int) error {
	certs, err := w.Store.ARIDueCertificates(ctx, limit)
	if err != nil {
		return err
	}
	for _, c := range certs {
		if err := w.pollOne(ctx, c); err != nil {
			w.logger().Warn("ari poll", "certificate", c.ID, "err", err)
		}
	}
	return nil
}

// pollOne polls cert's current version's ARI window and, when the CA
// answers, stores it (ari_window_start/end, ari_checked_at, ari_retry_after)
// and lowers next_renew_at (never raises it, and only while cert's last
// attempt did not fail) into the window when that is earlier than the
// renewal-policy date already scheduled. cert is not managed, has no
// current version, or its effective renewPolicy.useAri is unset: this is a
// no-op (Deviations/global constraint: an ARI window is never applied to
// an unmanaged certificate). A CA error (including a directory with no
// renewalInfo endpoint at all) is returned for the caller to log; nothing
// is written for cert in that case.
func (w *ARIPollWorker) pollOne(ctx context.Context, cert Certificate) error {
	if !cert.Managed || cert.CurrentVersionID == nil {
		return nil
	}
	eff, err := w.Store.EffectiveFor(ctx, cert)
	if err != nil {
		return err
	}
	if !eff.RenewPolicy.Value.UseARI {
		return nil
	}
	v, err := w.Certs.Get(ctx, cert.ID, *cert.CurrentVersionID)
	if err != nil {
		return err
	}
	if v.CAID == nil {
		return nil
	}
	ca, err := w.Store.GetCA(ctx, cert.OrgID, *v.CAID)
	if err != nil {
		return err
	}
	m, err := w.Certs.Material(ctx, cert.ID, *cert.CurrentVersionID, false)
	if err != nil {
		return err
	}
	leaf, err := x509.ParseCertificate(m.LeafDER)
	if err != nil {
		return err
	}
	win, err := w.NewSigner(ca).RenewalInfo(ctx, leaf)
	if err != nil {
		return err
	}
	if win == nil {
		return nil
	}
	now := w.Now()
	retryAfter := win.RetryAfter
	if retryAfter <= 0 {
		retryAfter = ariDefaultRetryAfter
	}
	if err := w.Store.SetARIWindow(ctx, cert.ID, *cert.CurrentVersionID, win.Start, win.End, now, now.Add(retryAfter)); err != nil {
		return err
	}
	if cert.NextRenewAt == nil {
		return nil
	}
	candidate := NextRenewAtARI(*cert.NextRenewAt, win, now, w.Rand)
	return w.Store.LowerNextRenewAt(ctx, cert.ID, *cert.CurrentVersionID, candidate)
}

// ARIDueCertificates returns certificates due for an ARI poll (see
// ARIPollWorker): managed, with a current version, status active, and
// ari_retry_after has passed or was never set. Whether renewPolicy.useAri
// is actually set is resolved separately per certificate (pollOne, via
// Store.EffectiveFor).
func (s *Store) ARIDueCertificates(ctx context.Context, limit int) ([]Certificate, error) {
	rows, err := s.q.ListARIDue(ctx, int32(limit))
	if err != nil {
		return nil, err
	}
	out := make([]Certificate, len(rows))
	for i, r := range rows {
		c, err := certFromRow(r)
		if err != nil {
			return nil, err
		}
		out[i] = c
	}
	return out, nil
}

// SetARIWindow stores a fetched ARI window for certID, only while
// current_version_id still matches versionID (see the SetARIWindow SQL
// query's comment).
func (s *Store) SetARIWindow(ctx context.Context, certID, versionID uuid.UUID, start, end, checkedAt, retryAfter time.Time) error {
	return s.q.SetARIWindow(ctx, sqlcgen.SetARIWindowParams{ID: certID, CurrentVersionID: &versionID,
		AriWindowStart: &start, AriWindowEnd: &end, AriCheckedAt: &checkedAt, AriRetryAfter: &retryAfter})
}

// LowerNextRenewAt moves certID's next_renew_at to candidate when that is
// earlier, only while current_version_id still matches versionID and the
// certificate has not failed its last attempt (see the LowerNextRenewAt
// SQL query's comment).
func (s *Store) LowerNextRenewAt(ctx context.Context, certID, versionID uuid.UUID, candidate time.Time) error {
	return s.q.LowerNextRenewAt(ctx, sqlcgen.LowerNextRenewAtParams{ID: certID, CurrentVersionID: &versionID, NextRenewAt: &candidate})
}
