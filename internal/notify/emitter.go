package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"unicode/utf8"

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
	if !IsKind(ev.Kind) {
		return false, fmt.Errorf("notify: unknown event kind %q", ev.Kind)
	}
	// An empty DedupeKey would collapse every empty-key event of this kind
	// into the first one ever emitted (notification_events.dedupe_key is
	// UNIQUE) — batch-1 review finding 4.
	if ev.DedupeKey == "" {
		return false, errors.New("notify: dedupe key is required")
	}
	ev.Severity = SeverityOf(ev.Kind)
	// Resource.Type is fixed per kind (ADR 0017), never the caller's
	// choice — batch-1 review finding 4.
	ev.Resource.Type = ResourceTypeOf(ev.Kind)
	ev.Summary = truncateUTF8(ev.Summary, maxSummary)

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

func (e *Emitter) emitTx(ctx context.Context, tx pgx.Tx, ev Event) (bool, error) {
	q := sqlcgen.New(tx)

	details := ev.Details
	if details == nil {
		details = map[string]any{}
	}
	detailsJSON, err := json.Marshal(details)
	if err != nil {
		return false, fmt.Errorf("notify: encode event details: %w", err)
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
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("notify: insert event: %w", err)
	}

	channelIDs, err := q.MatchingChannels(ctx, sqlcgen.MatchingChannelsParams{
		OrgID: ev.OrgID, Kind: ev.Kind, Severity: ev.Severity,
	})
	if err != nil {
		return false, fmt.Errorf("notify: match channels: %w", err)
	}

	for _, chID := range channelIDs {
		if err := q.InsertNotificationDelivery(ctx, sqlcgen.InsertNotificationDeliveryParams{
			EventID: id, ChannelID: chID,
		}); err != nil {
			return false, fmt.Errorf("notify: insert delivery: %w", err)
		}
		if _, err := e.River.InsertTx(ctx, tx, DeliverArgs{EventID: id, ChannelID: chID}, nil); err != nil {
			return false, fmt.Errorf("notify: enqueue delivery: %w", err)
		}
	}
	return true, nil
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
