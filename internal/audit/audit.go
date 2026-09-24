// Package audit records append-only, hash-chained audit events.
package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

const lockKey int64 = 0x43460002

// ErrChainBroken means a stored event does not match its hash chain.
var ErrChainBroken = errors.New("audit: hash chain broken")

var genesis = make([]byte, sha256.Size)

// Event is one auditable action. Empty actor fields are filled from the
// request principal, or "system".
type Event struct {
	Action       string
	ResourceType string
	ResourceID   string
	OrgID        *uuid.UUID
	Details      map[string]any
	ActorType    string
	ActorID      string
}

type ipKey struct{}

// WithIP attaches the client IP recorded with events.
func WithIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ipKey{}, ip)
}

func ipFrom(ctx context.Context) string {
	ip, _ := ctx.Value(ipKey{}).(string)
	return ip
}

// Auditor writes and verifies the audit chain.
type Auditor struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// New returns an Auditor.
func New(pool *pgxpool.Pool) *Auditor { return &Auditor{pool: pool, now: time.Now} }

// Record appends e to the chain. Appends are serialized by an advisory lock.
func (a *Auditor) Record(ctx context.Context, e Event) error {
	if e.Action == "" || e.ResourceType == "" {
		return errors.New("audit: action and resource type are required")
	}
	actorType, actorID := e.ActorType, e.ActorID
	if actorType == "" {
		if p, ok := authn.PrincipalFrom(ctx); ok {
			actorType, actorID = p.Kind, p.UserID.String()
		} else {
			actorType = "system"
		}
	}
	details := e.Details
	if details == nil {
		details = map[string]any{}
	}
	canon, err := canonicalJSON(details)
	if err != nil {
		return fmt.Errorf("audit: details: %w", err)
	}
	row := sqlcgen.InsertAuditEventParams{
		Ts: a.now().UTC().Truncate(time.Microsecond), ActorType: actorType, ActorID: actorID,
		Action: e.Action, ResourceType: e.ResourceType, ResourceID: e.ResourceID,
		OrgID: e.OrgID, Ip: ipFrom(ctx), Details: canon,
	}
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return fmt.Errorf("audit: lock: %w", err)
	}
	q := sqlcgen.New(tx)
	prev, err := q.LastAuditHash(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		prev = genesis
	} else if err != nil {
		return fmt.Errorf("audit: last hash: %w", err)
	}
	row.PrevHash = prev
	row.Hash = chainHash(prev, row.Ts, row.ActorType, row.ActorID, row.Action, row.ResourceType, row.ResourceID, row.OrgID, row.Ip, canon)
	if _, err := q.InsertAuditEvent(ctx, row); err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	return tx.Commit(ctx)
}

// Verify walks the whole chain and returns the number of events checked.
func (a *Auditor) Verify(ctx context.Context) (int64, error) {
	const page = 500
	q := sqlcgen.New(a.pool)
	prev := genesis
	var after, n int64
	for {
		rows, err := q.ListAuditEventsAsc(ctx, sqlcgen.ListAuditEventsAscParams{ID: after, Limit: page})
		if err != nil {
			return n, err
		}
		for _, ev := range rows {
			canon, err := canonicalJSON(json.RawMessage(ev.Details))
			if err != nil {
				return n, fmt.Errorf("%w at id %d: %w", ErrChainBroken, ev.ID, err)
			}
			want := chainHash(prev, ev.Ts, ev.ActorType, ev.ActorID, ev.Action, ev.ResourceType, ev.ResourceID, ev.OrgID, ev.Ip, canon)
			if !bytes.Equal(ev.PrevHash, prev) || !bytes.Equal(ev.Hash, want) {
				return n, fmt.Errorf("%w at id %d", ErrChainBroken, ev.ID)
			}
			prev, after = ev.Hash, ev.ID
			n++
		}
		if len(rows) < page {
			return n, nil
		}
	}
}

func chainHash(prev []byte, ts time.Time, actorType, actorID, action, resourceType, resourceID string, orgID *uuid.UUID, ip string, details []byte) []byte {
	org := ""
	if orgID != nil {
		org = orgID.String()
	}
	h := sha256.New()
	h.Write(prev)
	for _, f := range []string{ts.UTC().Format(time.RFC3339Nano), actorType, actorID, action, resourceType, resourceID, org, ip} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	h.Write(details)
	return h.Sum(nil)
}

// canonicalJSON re-encodes v through any, giving sorted keys and compact
// output regardless of how Postgres jsonb reformatted it.
func canonicalJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var generic any
	if err := json.Unmarshal(b, &generic); err != nil {
		return nil, err
	}
	return json.Marshal(generic)
}
