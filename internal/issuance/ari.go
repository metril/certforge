package issuance

import (
	"context"
	"crypto/x509"
	"errors"
	"log/slog"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/riverqueue/river"
	"golang.org/x/sync/errgroup"

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

// ariConcurrency bounds how many certificates of one PollDue page are
// polled at once.
const ariConcurrency = 4

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
	Store *Store
	Certs *certstore.Store
	// NewSigner builds the signer for a CA (SignerFactory.New in
	// production, wired the same as IssueWorker.NewSigner). It never needs
	// Config.Account: RenewalInfo is an unauthenticated GET (RFC 9773), so
	// the poll never loads or decrypts an ACME account key.
	NewSigner func(ctx context.Context, ca CA) (signer.Signer, error)
	Now       func() time.Time
	Rand      func() float64
	Log       *slog.Logger
}

// NewARIPollWorker wires production defaults. NewSigner is left nil: the
// caller wires it to a *SignerFactory before riverClient.Start, same as
// IssueWorker's own.
func NewARIPollWorker(store *Store, certs *certstore.Store) *ARIPollWorker {
	return &ARIPollWorker{Store: store, Certs: certs, Now: time.Now, Rand: rand.Float64, Log: slog.Default()}
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

// ariRun is the per-PollDue-run cache: global and org defaults, CAs and
// signers are each read or built once per run instead of per certificate,
// and retry bumps are collected for one batched write per page. A nil
// bumps (the post-issuance single-certificate poll) writes each bump at
// once. All methods are safe for concurrent use.
type ariRun struct {
	w       *ARIPollWorker
	mu      sync.Mutex
	signers map[uuid.UUID]signer.Signer
	global  *Defaults
	orgs    map[uuid.UUID]Defaults
	cas     map[[2]uuid.UUID]CA
	batch   bool
	bumps   []ariBump
}

type ariBump struct {
	cert, version uuid.UUID
	at            time.Time
}

func (w *ARIPollWorker) newRun(signers map[uuid.UUID]signer.Signer, batch bool) *ariRun {
	return &ariRun{w: w, signers: signers, orgs: map[uuid.UUID]Defaults{}, cas: map[[2]uuid.UUID]CA{}, batch: batch}
}

// PollDue polls every due certificate, walking Store.ARIDueCertificates
// with a plain id keyset cursor a page (pageSize) at a time (fix round 1),
// rather than a single page: a certificate that is skipped or errors also
// has its own ari_retry_after bumped (bumpRetryAfter) so it drops out of
// later pages too, but the cursor itself always advances past whatever a
// page just returned regardless of outcome, so a certificate whose bump
// write itself fails can never make this loop repeat the same page
// forever. One certificate's error is logged and never stops the rest of
// the batch, or fails the job (the most common cause — a CA directory that
// does not publish a renewalInfo endpoint at all — would otherwise repeat
// for every certificate on that CA on every run).
//
// Fix round 2: the due query already carries each certificate's current CA
// id and leaf, defaults, CAs and signers are cached for the whole run
// (ariRun; one Signer per CA also fetches the ACME directory at most once),
// a page's certificates are polled with bounded concurrency, and the
// page's retry bumps are written in one statement.
func (w *ARIPollWorker) PollDue(ctx context.Context, pageSize int) error {
	run := w.newRun(map[uuid.UUID]signer.Signer{}, true)
	var cursor *uuid.UUID
	for {
		due, err := w.Store.ARIDueCertificates(ctx, pageSize, cursor)
		if err != nil {
			return err
		}
		if len(due) == 0 {
			return nil
		}
		var g errgroup.Group
		g.SetLimit(ariConcurrency)
		for _, d := range due {
			g.Go(func() error {
				if err := run.poll(ctx, d.Certificate, &ariLeaf{caID: d.CAID, der: d.LeafDER}); err != nil {
					w.logger().Warn("ari poll", "certificate", d.ID, "err", err)
				}
				return nil
			})
		}
		_ = g.Wait()
		run.flushBumps(ctx)
		last := due[len(due)-1].ID
		cursor = &last
		if len(due) < pageSize {
			return nil
		}
	}
}

// signerFor returns the cached signer for ca, building it via NewSigner on
// a miss. A nil cache (the post-issuance poll) skips caching.
func (r *ariRun) signerFor(ctx context.Context, ca CA) (signer.Signer, error) {
	if r.signers == nil {
		return r.w.NewSigner(ctx, ca)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if s, ok := r.signers[ca.ID]; ok {
		return s, nil
	}
	s, err := r.w.NewSigner(ctx, ca)
	if err != nil {
		return nil, err
	}
	r.signers[ca.ID] = s
	return s, nil
}

// getCA returns the org's CA, cached for the run (errors are not cached).
func (r *ariRun) getCA(ctx context.Context, orgID, id uuid.UUID) (CA, error) {
	k := [2]uuid.UUID{orgID, id}
	r.mu.Lock()
	defer r.mu.Unlock()
	if ca, ok := r.cas[k]; ok {
		return ca, nil
	}
	ca, err := r.w.Store.GetCA(ctx, orgID, id)
	if err != nil {
		return CA{}, err
	}
	r.cas[k] = ca
	return ca, nil
}

// effective resolves cert's effective defaults from the run's cached global
// and org levels.
func (r *ariRun) effective(ctx context.Context, cert Certificate) (Effective, error) {
	r.mu.Lock()
	if r.global == nil {
		g, err := r.w.Store.GlobalDefaults(ctx)
		if err != nil {
			r.mu.Unlock()
			return Effective{}, err
		}
		r.global = &g
	}
	g := *r.global
	o, ok := r.orgs[cert.OrgID]
	if !ok {
		var err error
		if o, err = r.w.Store.OrgDefaults(ctx, cert.OrgID); err != nil {
			r.mu.Unlock()
			return Effective{}, err
		}
		r.orgs[cert.OrgID] = o
	}
	r.mu.Unlock()
	return effectiveWith(ctx, cert.OrgID, g, o, cert.Overrides, r.getCA)
}

// bumpRetryAfter defers cert's next poll by d (or ariDefaultRetryAfter when
// d <= 0) so a certificate skipped or erroring before a window was fetched
// does not occupy ListARIDueWithLeaf's next page, or the next run's first
// page, forever (fix round 1). In a PollDue run the bump is collected for
// flushBumps; otherwise it is written at once. Best-effort: a write
// failure is logged and never layered into the caller's own error.
func (r *ariRun) bumpRetryAfter(ctx context.Context, cert Certificate, d time.Duration) {
	if d <= 0 {
		d = ariDefaultRetryAfter
	}
	at := r.w.Now().Add(d)
	if r.batch {
		r.mu.Lock()
		r.bumps = append(r.bumps, ariBump{cert.ID, *cert.CurrentVersionID, at})
		r.mu.Unlock()
		return
	}
	if err := r.w.Store.BumpARIRetryAfter(ctx, cert.ID, *cert.CurrentVersionID, at); err != nil {
		r.w.logger().Warn("ari retry-after bump", "certificate", cert.ID, "err", err)
	}
}

// flushBumps writes the collected bumps in one statement.
func (r *ariRun) flushBumps(ctx context.Context) {
	r.mu.Lock()
	bumps := r.bumps
	r.bumps = nil
	r.mu.Unlock()
	if len(bumps) == 0 {
		return
	}
	if err := r.w.Store.BumpARIRetryAfterMany(ctx, bumps); err != nil {
		r.w.logger().Warn("ari retry-after bump", "certificates", len(bumps), "err", err)
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

// pollOne polls one certificate's ARI window outside a PollDue run (the
// post-issuance poll, IssueWorker.succeed), reading its version and
// defaults itself. signers, when non-nil, caches one signer.Signer per CA
// (the post-issuance poll passes nil). See ariRun.poll for the rules.
func (w *ARIPollWorker) pollOne(ctx context.Context, cert Certificate, signers map[uuid.UUID]signer.Signer) error {
	return w.newRun(signers, false).poll(ctx, cert, nil)
}

// ariLeaf is a due certificate's current version's CA id and leaf DER,
// already read by the due query.
type ariLeaf struct {
	caID *uuid.UUID
	der  []byte
}

// poll polls cert's current version's ARI window and, when the CA answers,
// stores it (ari_window_start/end, ari_checked_at, ari_retry_after) and
// lowers next_renew_at (never raises it, and only while cert's last attempt
// did not fail) into the window when that is earlier than the
// renewal-policy date already scheduled. cert is not managed, has no
// current version, or its effective renewPolicy.useAri is unset: this is a
// no-op (Deviations/global constraint: an ARI window is never applied to
// an unmanaged certificate) — neither of those two cases can appear in
// ListARIDueWithLeaf's own result set, so no ari_retry_after bump is
// needed for them; every other skip or error case (useAri off cannot occur
// alongside them, but is included for symmetry; no CA recorded for the
// current version; any error reading the version, its CA or its material;
// a RenewalInfo error, including a CA directory with no renewalInfo
// endpoint at all) bumps ari_retry_after (fix round 1) so the certificate
// is not immediately retried every subsequent page or run. leaf is the
// version's CA id and leaf when the caller already has them (PollDue); nil
// reads them from the certificate store.
func (r *ariRun) poll(ctx context.Context, cert Certificate, leaf *ariLeaf) error {
	w := r.w
	if !cert.Managed || cert.CurrentVersionID == nil {
		return nil
	}
	eff, err := r.effective(ctx, cert)
	if err != nil {
		return err
	}
	if !eff.RenewPolicy.Value.UseARI {
		r.bumpRetryAfter(ctx, cert, 0)
		return nil
	}
	var caID *uuid.UUID
	if leaf != nil {
		caID = leaf.caID
	} else {
		v, err := w.Certs.Get(ctx, cert.ID, *cert.CurrentVersionID)
		if err != nil {
			r.bumpRetryAfter(ctx, cert, 0)
			return err
		}
		caID = v.CAID
	}
	if caID == nil {
		r.bumpRetryAfter(ctx, cert, 0)
		return nil
	}
	ca, err := r.getCA(ctx, cert.OrgID, *caID)
	if err != nil {
		r.bumpRetryAfter(ctx, cert, retryAfterFromErr(err))
		return err
	}
	// A private CA (localca, vaultpki) has no ACME Renewal Information to
	// poll (Task 9 contract: "skip certificates whose effective CA is not
	// acme"); useAri is ignored for it and ariWindow stays null.
	if ca.Private() {
		r.bumpRetryAfter(ctx, cert, 0)
		return nil
	}
	var der []byte
	if leaf != nil {
		der = leaf.der
	} else {
		m, err := w.Certs.Material(ctx, cert.ID, *cert.CurrentVersionID, false)
		if err != nil {
			r.bumpRetryAfter(ctx, cert, 0)
			return err
		}
		der = m.LeafDER
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		r.bumpRetryAfter(ctx, cert, 0)
		return err
	}
	sig, err := r.signerFor(ctx, ca)
	if err != nil {
		r.bumpRetryAfter(ctx, cert, retryAfterFromErr(err))
		return err
	}
	win, err := sig.RenewalInfo(ctx, parsed)
	if err != nil {
		r.bumpRetryAfter(ctx, cert, retryAfterFromErr(err))
		return err
	}
	if win == nil {
		r.bumpRetryAfter(ctx, cert, 0)
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

// ariDue is one due certificate with its current version's CA id and leaf.
type ariDue struct {
	Certificate
	CAID    *uuid.UUID
	LeafDER []byte
}

// ARIDueCertificates returns one page (limit certificates, ordered by id)
// of certificates due for an ARI poll (see ARIPollWorker): managed, with a
// current version, status active, and ari_retry_after has passed or was
// never set. after is nil for the first page, else the previous page's
// last id (fix round 1: PollDue walks every page with this, not just one).
// Each carries its current version's CA id and leaf DER. Whether
// renewPolicy.useAri is actually set is resolved separately per
// certificate (ariRun.effective).
func (s *Store) ARIDueCertificates(ctx context.Context, limit int, after *uuid.UUID) ([]ariDue, error) {
	p := sqlcgen.ListARIDueWithLeafParams{PageLimit: int32(limit)}
	if after != nil {
		p.HasCursor, p.LastID = true, *after
	}
	rows, err := s.q.ListARIDueWithLeaf(ctx, p)
	if err != nil {
		return nil, err
	}
	out := make([]ariDue, len(rows))
	for i, r := range rows {
		c, err := certFromRow(r.Certificate)
		if err != nil {
			return nil, err
		}
		out[i] = ariDue{Certificate: c, CAID: r.VersionCaID, LeafDER: r.VersionLeafDer}
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

// BumpARIRetryAfterMany is BumpARIRetryAfter for a batch, in one statement.
func (s *Store) BumpARIRetryAfterMany(ctx context.Context, bumps []ariBump) error {
	p := sqlcgen.BumpARIRetryAfterManyParams{}
	for _, b := range bumps {
		p.Ids = append(p.Ids, b.cert)
		p.VersionIds = append(p.VersionIds, b.version)
		p.RetryAfters = append(p.RetryAfters, b.at)
	}
	return s.q.BumpARIRetryAfterMany(ctx, p)
}
