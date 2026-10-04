package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/db/sqlcgen"
)

// maxSummary bounds Event.Summary (Shared contract: Event.summary, <= 500).
const maxSummary = 500

// Inserter is the subset of *river.Client[pgx.Tx] Emitter needs to enqueue
// a delivery job inside the same transaction as the event/delivery rows;
// production passes the real river client, tests a fake (same pattern as
// deploy.Inserter/kek.Inserter).
type Inserter interface {
	InsertTx(ctx context.Context, tx pgx.Tx, args river.JobArgs, opts *river.InsertOpts) (*rivertype.JobInsertResult, error)
}

// ManyInserter is the optional bulk form of Inserter: when River implements
// it, EmitBatch enqueues a chunk's delivery jobs in one InsertManyTx
// (*river.Client does); otherwise it falls back to one InsertTx per job.
type ManyInserter interface {
	InsertManyTx(ctx context.Context, tx pgx.Tx, params []river.InsertManyParams) ([]*rivertype.JobInsertResult, error)
}

// Emitter records a notification_events row (exact-once, by DedupeKey) and
// enqueues one certforge_notify_deliver job per matching, enabled channel.
type Emitter struct {
	Pool  *pgxpool.Pool
	River Inserter
	Log   *slog.Logger
}

// Emit validates kind, fills Severity (SeverityOf) and truncates Summary to
// maxSummary, then inserts the event and — only if it was not a duplicate
// — one pending delivery and one certforge_notify_deliver job per matching
// channel (task-3 brief). It reports whether the event was newly recorded
// (false, nil means DedupeKey already fired; that is not an error).
//
// tx nil means Emit opens and commits its own transaction; a non-nil tx
// (an event raised as part of a larger write, e.g. issuance's own
// transaction) is used as-is and left for the caller to commit or roll
// back — a caller-tx rollback then leaves nothing behind, event or job
// alike (TestEmitInsideCallerTx).
func (e *Emitter) Emit(ctx context.Context, tx pgx.Tx, ev Event) (bool, error) {
	ev, err := prepare(ev)
	if err != nil {
		return false, err
	}
	if tx != nil {
		return e.emitTx(ctx, tx, ev)
	}

	own, err := e.Pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = own.Rollback(ctx) }()
	created, err := e.emitTx(ctx, own, ev)
	if err != nil {
		return false, err
	}
	if err := own.Commit(ctx); err != nil {
		return false, err
	}
	return created, nil
}

// prepare validates ev and fills the fields the emitter owns: Severity,
// Resource.Type and a truncated Summary. Shared by Emit and EmitBatch.
func prepare(ev Event) (Event, error) {
	if !IsKind(ev.Kind) {
		return ev, fmt.Errorf("notify: unknown event kind %q", ev.Kind)
	}
	// An empty DedupeKey would collapse every empty-key event of this kind
	// into the first one ever emitted (notification_events.dedupe_key is
	// UNIQUE) — batch-1 review finding 4.
	if ev.DedupeKey == "" {
		return ev, errors.New("notify: dedupe key is required")
	}
	ev.Severity = SeverityOf(ev.Kind)
	// Resource.Type is fixed per kind (ADR 0017), never the caller's
	// choice — batch-1 review finding 4.
	ev.Resource.Type = ResourceTypeOf(ev.Kind)
	ev.Summary = truncateUTF8(ev.Summary, maxSummary)
	return ev, nil
}

func (e *Emitter) emitTx(ctx context.Context, tx pgx.Tx, ev Event) (bool, error) {
	created, jobs, err := e.record(ctx, tx, ev, nil)
	if err != nil || !created {
		return false, err
	}
	for _, a := range jobs {
		if _, err := e.River.InsertTx(ctx, tx, a, nil); err != nil {
			return false, fmt.Errorf("notify: enqueue delivery: %w", err)
		}
	}
	return true, nil
}

// record inserts the (prepared) event and, unless it was a duplicate, one
// pending delivery per matching channel, returning the jobs to enqueue for
// them. match, when non-nil, replaces the per-event channel lookup (the
// batch path memoises it).
func (e *Emitter) record(ctx context.Context, tx pgx.Tx, ev Event, match func(sqlcgen.MatchingChannelsParams) ([]uuid.UUID, error)) (bool, []DeliverArgs, error) {
	q := sqlcgen.New(tx)

	details := ev.Details
	if details == nil {
		details = map[string]any{}
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return false, nil, fmt.Errorf("notify: encode event details: %w", err)
	}

	id, err := q.InsertNotificationEvent(ctx, sqlcgen.InsertNotificationEventParams{
		OrgID:        ev.OrgID,
		Kind:         ev.Kind,
		Severity:     ev.Severity,
		ResourceType: ev.Resource.Type,
		ResourceID:   ev.Resource.ID,
		ResourceName: ev.Resource.Name,
		Summary:      ev.Summary,
		Details:      detailsJSON,
		DedupeKey:    ev.DedupeKey,
	})
	// ON CONFLICT DO NOTHING RETURNING gives back zero rows when the
	// dedupe key already fired; sqlc's :one query surfaces that as
	// pgx.ErrNoRows, not a constraint-violation error — the normal outcome
	// for a duplicate, not a database error (TestEmitDuplicateIsNoop).
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil, nil
	}
	if err != nil {
		return false, nil, fmt.Errorf("notify: insert event: %w", err)
	}

	mp := sqlcgen.MatchingChannelsParams{OrgID: ev.OrgID, Kind: ev.Kind, Severity: ev.Severity}
	var channelIDs []uuid.UUID
	if match != nil {
		channelIDs, err = match(mp)
	} else {
		channelIDs, err = q.MatchingChannels(ctx, mp)
	}
	if err != nil {
		return false, nil, fmt.Errorf("notify: match channels: %w", err)
	}

	jobs := make([]DeliverArgs, 0, len(channelIDs))
	for _, chID := range channelIDs {
		if err := q.InsertNotificationDelivery(ctx, sqlcgen.InsertNotificationDeliveryParams{
			EventID: id, ChannelID: chID,
		}); err != nil {
			return false, nil, fmt.Errorf("notify: insert delivery: %w", err)
		}
		jobs = append(jobs, DeliverArgs{EventID: id, ChannelID: chID})
	}
	return true, jobs, nil
}

// truncateUTF8 cuts s to at most maxBytes bytes, trimming back further if
// the cut landed inside a multi-byte rune (same trick as
// deploy.truncateUTF8: an incomplete trailing sequence makes Postgres
// reject the string outright, since text columns must be valid UTF-8).
func truncateUTF8(s string, maxBytes int) string {
	if len(s) <= maxBytes {
		return s
	}
	s = s[:maxBytes]
	for len(s) > 0 {
		r, size := utf8.DecodeLastRuneInString(s)
		if r != utf8.RuneError || size != 1 {
			break
		}
		s = s[:len(s)-1]
	}
	return s
}

// emitBatchChunk is how many events EmitBatch commits per transaction.
const emitBatchChunk = 100

type channelKey struct {
	org      uuid.UUID
	hasOrg   bool
	kind     string
	severity string
}

// EmitBatch emits many events like Emit(ctx, nil, ev) each (same
// validation, dedupe and delivery rows), but one transaction per chunk of
// emitBatchChunk with a savepoint per event, so one failing event rolls
// back only itself. The matching-channel lookup is memoised per (org,
// kind, severity) across the batch and a chunk's delivery jobs are
// enqueued together at its end. It returns how many events were newly
// recorded (duplicates are not errors) and the joined errors of the events
// or chunks that failed; every other event is still committed.
func (e *Emitter) EmitBatch(ctx context.Context, evs []Event) (int, error) {
	var errs []error
	created := 0
	memo := map[channelKey][]uuid.UUID{}
	for start := 0; start < len(evs); start += emitBatchChunk {
		end := min(start+emitBatchChunk, len(evs))
		n, err := e.emitChunk(ctx, evs[start:end], memo)
		created += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	return created, errors.Join(errs...)
}

func (e *Emitter) emitChunk(ctx context.Context, evs []Event, memo map[channelKey][]uuid.UUID) (int, error) {
	tx, err := e.Pool.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	var errs []error
	var jobs []river.InsertManyParams
	created := 0
	for _, ev := range evs {
		ev, err := prepare(ev)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		sp, err := tx.Begin(ctx)
		if err != nil {
			return 0, errors.Join(append(errs, err)...)
		}
		match := func(p sqlcgen.MatchingChannelsParams) ([]uuid.UUID, error) {
			k := channelKey{kind: p.Kind, severity: p.Severity}
			if p.OrgID != nil {
				k.org, k.hasOrg = *p.OrgID, true
			}
			if ids, ok := memo[k]; ok {
				return ids, nil
			}
			ids, err := sqlcgen.New(sp).MatchingChannels(ctx, p)
			if err == nil {
				memo[k] = ids
			}
			return ids, err
		}
		ok, args, err := e.record(ctx, sp, ev, match)
		if err != nil {
			_ = sp.Rollback(ctx)
			errs = append(errs, err)
			continue
		}
		if err := sp.Commit(ctx); err != nil {
			return 0, errors.Join(append(errs, err)...)
		}
		if ok {
			created++
		}
		for _, a := range args {
			jobs = append(jobs, river.InsertManyParams{Args: a})
		}
	}
	if err := e.enqueueMany(ctx, tx, jobs); err != nil {
		return 0, errors.Join(append(errs, err)...)
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, errors.Join(append(errs, err)...)
	}
	return created, errors.Join(errs...)
}

func (e *Emitter) enqueueMany(ctx context.Context, tx pgx.Tx, jobs []river.InsertManyParams) error {
	if len(jobs) == 0 {
		return nil
	}
	if m, ok := e.River.(ManyInserter); ok {
		if _, err := m.InsertManyTx(ctx, tx, jobs); err != nil {
			return fmt.Errorf("notify: enqueue deliveries: %w", err)
		}
		return nil
	}
	for _, j := range jobs {
		if _, err := e.River.InsertTx(ctx, tx, j.Args, j.InsertOpts); err != nil {
			return fmt.Errorf("notify: enqueue delivery: %w", err)
		}
	}
	return nil
}
