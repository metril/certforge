package issuance

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"math/rand/v2"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/signer"
)

// ariPollBatch is the page size PollDue asks Store.ARIDueCertificates for;
// PollDue itself walks every page, not just the first.
const ariPollBatch = 500

// ariDefaultRetryAfter spaces out the next poll when the CA's RenewalInfo
// response carries no Retry-After of its own, and (fix round 1) whenever a
// certificate is skipped or errors before a window was actually fetched.
const ariDefaultRetryAfter = 6 * time.Hour

// ariTimeout bounds one ARIPollWorker run: it may sequentially poll
// hundreds of certificates across many CAs, well past river's 1-minute
// worker default (fix round 1).
const ariTimeout = 30 * time.Minute

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

// Timeout implements river.Worker (fix round 1: see ariTimeout).
func (w *ARIPollWorker) Timeout(*river.Job[ARIPollArgs]) time.Duration { return ariTimeout }

// Work implements river.Worker.
func (w *ARIPollWorker) Work(ctx context.Context, _ *river.Job[ARIPollArgs]) error {
	return w.PollDue(ctx, ariPollBatch)
}

// PollDue polls every due certificate, walking Store.ARIDueCertificates
// with a plain id keyset cursor a page (pageSize) at a time (fix round 1),
// rather than a single page: a certificate that is skipped or errors also
// has its own ari_retry_after bumped (pollOne, via bumpRetryAfter) so it
// drops out of later pages too, but the cursor itself always advances past
// whatever a page just returned regardless of outcome, so a certificate
// whose bump write itself fails can never make this loop repeat the same
// page forever. One certificate's error is logged and never stops the rest
// of the batch, or fails the job (the most common cause — a CA directory
// that does not publish a renewalInfo endpoint at all — would otherwise
// repeat for every certificate on that CA on every run).
//
// signers caches one signer.Signer per CA (by id) for the whole call, not
// just one page, so certificates sharing a CA reuse the same Signer
// instance — which itself now fetches the ACME directory at most once per
// instance (acme.Signer.RenewalInfo) — instead of each paying for its own
// directory fetch (fix round 1).
func (w *ARIPollWorker) PollDue(ctx context.Context, pageSize int) error {
	signers := map[uuid.UUID]signer.Signer{}
	var cursor *uuid.UUID
	for {
		certs, err := w.Store.ARIDueCertificates(ctx, pageSize, cursor)
		if err != nil {
			return err
		}
		if len(certs) == 0 {
			return nil
		}
		for _, c := range certs {
			if err := w.pollOne(ctx, c, signers); err != nil {
				w.logger().Warn("ari poll", "certificate", c.ID, "err", err)
			}
		}
		last := certs[len(certs)-1].ID
		cursor = &last
		if len(certs) < pageSize {
			return nil
		}
	}
}

// signerFor returns signers[ca.ID], building and caching it via NewSigner
// on a miss (fix round 1). signers may be nil (an ad-hoc single-certificate
// call, for example the post-issuance poll), in which case caching is
// simply skipped.
func (w *ARIPollWorker) signerFor(signers map[uuid.UUID]signer.Signer, ca CA) signer.Signer {
	if signers == nil {
		return w.NewSigner(ca)
	}
	if s, ok := signers[ca.ID]; ok {
		return s
	}
	s := w.NewSigner(ca)
	signers[ca.ID] = s
	return s
}

// bumpRetryAfter defers cert's next poll by d (or ariDefaultRetryAfter when
// d <= 0) so a certificate skipped or erroring before a window was fetched
// does not occupy ListARIDue's next page, or the next run's first page,
// forever (fix round 1). Best-effort: a write failure here is logged and
// never layered into the caller's own error.
func (w *ARIPollWorker) bumpRetryAfter(ctx context.Context, cert Certificate, d time.Duration) {
	if d <= 0 {
		d = ariDefaultRetryAfter
	}
	if err := w.Store.BumpARIRetryAfter(ctx, cert.ID, *cert.CurrentVersionID, w.Now().Add(d)); err != nil {
		w.logger().Warn("ari retry-after bump", "certificate", cert.ID, "err", err)
	}
}

// retryAfterFromErr extracts a CA-supplied Retry-After from err, when it
// carries one (a *signer.Error from a 429/503), else 0 (bumpRetryAfter's
// own default then applies).
func retryAfterFromErr(err error) time.Duration {
	var se *signer.Error
	if errors.As(err, &se) && se.RetryAfter > 0 {
		return se.RetryAfter
	}
	return 0
}

// pollOne polls cert's current version's ARI window and, when the CA
// answers, stores it (ari_window_start/end, ari_checked_at, ari_retry_after)
// and lowers next_renew_at (never raises it, and only while cert's last
// attempt did not fail) into the window when that is earlier than the
// renewal-policy date already scheduled. cert is not managed, has no
// current version, or its effective renewPolicy.useAri is unset: this is a
// no-op (Deviations/global constraint: an ARI window is never applied to
// an unmanaged certificate) — neither of those two cases can appear in
// ListARIDue's own result set, so no ari_retry_after bump is needed for
// them; every other skip or error case (useAri off cannot occur alongside
// them, but is included for symmetry; no CA recorded for the current
// version; any error reading the version, its CA or its material; a
// RenewalInfo error, including a CA directory with no renewalInfo endpoint
// at all) bumps ari_retry_after (fix round 1) so the certificate is not
// immediately retried every subsequent page or run. signers, when non-nil,
// caches one signer.Signer per CA across the whole caller-defined run
// (PollDue passes one shared map; the post-issuance poll passes nil).
func (w *ARIPollWorker) pollOne(ctx context.Context, cert Certificate, signers map[uuid.UUID]signer.Signer) error {
	if !cert.Managed || cert.CurrentVersionID == nil {
		return nil
	}
	eff, err := w.Store.EffectiveFor(ctx, cert)
	if err != nil {
		return err
	}
	if !eff.RenewPolicy.Value.UseARI {
		w.bumpRetryAfter(ctx, cert, 0)
		return nil
	}
	v, err := w.Certs.Get(ctx, cert.ID, *cert.CurrentVersionID)
	if err != nil {
		w.bumpRetryAfter(ctx, cert, 0)
		return err
	}
	if v.CAID == nil {
		w.bumpRetryAfter(ctx, cert, 0)
		return nil
	}
	ca, err := w.Store.GetCA(ctx, cert.OrgID, *v.CAID)
	if err != nil {
		w.bumpRetryAfter(ctx, cert, retryAfterFromErr(err))
		return err
	}
	m, err := w.Certs.Material(ctx, cert.ID, *cert.CurrentVersionID, false)
	if err != nil {
		w.bumpRetryAfter(ctx, cert, 0)
		return err
	}
	leaf, err := x509.ParseCertificate(m.LeafDER)
	if err != nil {
		w.bumpRetryAfter(ctx, cert, 0)
		return err
	}
	win, err := w.signerFor(signers, ca).RenewalInfo(ctx, leaf)
	if err != nil {
		w.bumpRetryAfter(ctx, cert, retryAfterFromErr(err))
		return err
	}
	if win == nil {
		w.bumpRetryAfter(ctx, cert, 0)
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

// ARIDueCertificates returns one page (limit certificates, ordered by id)
// of certificates due for an ARI poll (see ARIPollWorker): managed, with a
// current version, status active, and ari_retry_after has passed or was
// never set. after is nil for the first page, else the previous page's
// last id (fix round 1: PollDue walks every page with this, not just one).
// Whether renewPolicy.useAri is actually set is resolved separately per
// certificate (pollOne, via Store.EffectiveFor).
func (s *Store) ARIDueCertificates(ctx context.Context, limit int, after *uuid.UUID) ([]Certificate, error) {
	p := sqlcgen.ListARIDueParams{PageLimit: int32(limit)}
	if after != nil {
		p.HasCursor, p.LastID = true, *after
	}
	rows, err := s.q.ListARIDue(ctx, p)
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

// BumpARIRetryAfter sets only certID's ari_retry_after, leaving any cached
// window untouched, only while current_version_id still matches versionID
// (fix round 1; see the BumpARIRetryAfter SQL query's comment).
func (s *Store) BumpARIRetryAfter(ctx context.Context, certID, versionID uuid.UUID, retryAfter time.Time) error {
	return s.q.BumpARIRetryAfter(ctx, sqlcgen.BumpARIRetryAfterParams{ID: certID, CurrentVersionID: &versionID, AriRetryAfter: &retryAfter})
}

// LowerNextRenewAt moves certID's next_renew_at to candidate when that is
// earlier, only while current_version_id still matches versionID and the
// certificate has not failed its last attempt (see the LowerNextRenewAt
// SQL query's comment).
func (s *Store) LowerNextRenewAt(ctx context.Context, certID, versionID uuid.UUID, candidate time.Time) error {
	return s.q.LowerNextRenewAt(ctx, sqlcgen.LowerNextRenewAtParams{ID: certID, CurrentVersionID: &versionID, NextRenewAt: &candidate})
}
