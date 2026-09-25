// Package audit records append-only audit events in a hash chain keyed with
// HMAC-SHA256 (ADR 0008).
package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

const lockKey int64 = 0x43460002

// chainKeyedSettingKey records, informationally, that Rechain has run and no
// legacy sha256 row remained at that point. It is never the security gate:
// a settings-table flag can drift from the chain's actual contents (rolled
// back, edited by a bug, restored from an older backup), so the real
// downgrade gate is the monotonic rule enforced in Check and Rechain below
// (controller ruling, fix round 1) — once any hmac-sha256 row has been seen
// walking the chain in order, no later row may be sha256, full stop.
const chainKeyedSettingKey = "audit.chain_keyed"

// ErrChainBroken means a stored event does not match its hash chain.
var ErrChainBroken = errors.New("audit: hash chain broken")

var genesis = make([]byte, sha256.Size)

// Chain hash algorithms, stored per row in audit_events.hash_alg.
const (
	HashAlgLegacy = "sha256"      // Phase 1 rows until Rechain converts them
	HashAlgHMAC   = "hmac-sha256" // keyed with crypto.DeriveKey(kek, "certforge-audit")
)

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

// IPFrom returns the client IP set by WithIP.
func IPFrom(ctx context.Context) string {
	ip, _ := ctx.Value(ipKey{}).(string)
	return ip
}

// Auditor writes and verifies the audit chain.
type Auditor struct {
	pool *pgxpool.Pool
	key  []byte
	now  func() time.Time
}

// New returns an Auditor keyed with key. key must be a non-empty HMAC key
// (crypto.DeriveKey(kek, "certforge-audit")); a nil or empty key is a
// programming error, not a silent fallback to the unkeyed algorithm.
func New(pool *pgxpool.Pool, key []byte) *Auditor {
	if len(key) == 0 {
		panic("audit: New called with a nil or empty key")
	}
	return &Auditor{pool: pool, key: key, now: time.Now}
}

// Record appends e to the chain. Appends are serialized by an advisory lock.
func (a *Auditor) Record(ctx context.Context, e Event) error {
	if e.Action == "" || e.ResourceType == "" {
		return errors.New("audit: action and resource type are required")
	}
	actorType, actorID := e.ActorType, e.ActorID
	if actorType == "" {
		if p, ok := authn.PrincipalFrom(ctx); ok {
			actorType, actorID = p.Kind, p.ActorID()
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
		ActorType: actorType, ActorID: actorID,
		Action: e.Action, ResourceType: e.ResourceType, ResourceID: e.ResourceID,
		OrgID: e.OrgID, Ip: IPFrom(ctx), Details: canon, HashAlg: HashAlgHMAC,
	}
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("audit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return fmt.Errorf("audit: lock: %w", err)
	}
	// Stamp ts only after the lock is held, so id order and ts order agree
	// with chain order under contention.
	row.Ts = a.now().UTC().Truncate(time.Microsecond)
	q := sqlcgen.New(tx)
	prev, err := q.LastAuditHash(ctx)
	if errors.Is(err, pgx.ErrNoRows) {
		prev = genesis
	} else if err != nil {
		return fmt.Errorf("audit: last hash: %w", err)
	}
	row.PrevHash = prev
	row.Hash = a.sum(HashAlgHMAC, prev, row.Ts, row.ActorType, row.ActorID, row.Action, row.ResourceType, row.ResourceID, row.OrgID, row.Ip, canon)
	if _, err := q.InsertAuditEvent(ctx, row); err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	return tx.Commit(ctx)
}

// VerifyResult is the outcome of walking the chain.
type VerifyResult struct {
	OK         bool
	Count      int64  // rows that verified
	BrokenAtID int64  // first bad row when !OK
	HeadHash   []byte // hash of the last good row
}

// Check walks the whole chain. A mismatch is a result, not an error. The
// downgrade gate is monotonic and depends only on the rows themselves, never
// on the informational chainKeyedSettingKey flag: once a hmac-sha256 row has
// been seen (in chain order), any later sha256 row is reported broken
// outright, even one correctly chained under its own stored algorithm —
// tampering can forge a legacy-formula hash without the key, so a row's own
// internal consistency proves nothing once a keyed row has already appeared.
func (a *Auditor) Check(ctx context.Context) (VerifyResult, error) {
	const page = 500
	q := sqlcgen.New(a.pool)
	res := VerifyResult{OK: true, HeadHash: genesis}
	prev := genesis
	var after int64
	seenHMAC := false
	for {
		rows, err := q.ListAuditEventsAsc(ctx, sqlcgen.ListAuditEventsAscParams{ID: after, Limit: page})
		if err != nil {
			return res, err
		}
		for _, ev := range rows {
			if seenHMAC && ev.HashAlg != HashAlgHMAC {
				res.OK, res.BrokenAtID = false, ev.ID
				return res, nil
			}
			if ev.HashAlg == HashAlgHMAC {
				seenHMAC = true
			}
			if !a.rowOK(ev, prev) {
				res.OK, res.BrokenAtID = false, ev.ID
				return res, nil
			}
			prev, after, res.HeadHash = ev.Hash, ev.ID, ev.Hash
			res.Count++
		}
		if len(rows) < page {
			return res, nil
		}
	}
}

// Verify walks the chain and returns the number of events checked, or an
// error wrapping ErrChainBroken.
func (a *Auditor) Verify(ctx context.Context) (int64, error) {
	r, err := a.Check(ctx)
	if err != nil {
		return r.Count, err
	}
	if !r.OK {
		return r.Count, fmt.Errorf("%w at id %d", ErrChainBroken, r.BrokenAtID)
	}
	return r.Count, nil
}

func (a *Auditor) rowOK(ev sqlcgen.AuditEvent, prev []byte) bool {
	canon, err := canonicalJSON(json.RawMessage(ev.Details))
	if err != nil {
		return false
	}
	want := a.sum(ev.HashAlg, prev, ev.Ts, ev.ActorType, ev.ActorID, ev.Action, ev.ResourceType, ev.ResourceID, ev.OrgID, ev.Ip, canon)
	return want != nil && bytes.Equal(ev.PrevHash, prev) && bytes.Equal(ev.Hash, want)
}

// Rechain converts the chain to HMAC-SHA256 once, under the append advisory
// lock. Every row is first verified with its stored algorithm — subject to
// the same monotonic downgrade gate as Check, so a sha256 row appended after
// a hmac-sha256 row is refused rather than laundered into a freshly-rewritten
// valid HMAC row — and if any check fails, nothing is changed and
// ErrChainBroken is returned. It does not disable the append-only trigger
// (that would need table ownership); the trigger itself allows the
// three-column update Rechain performs (migration 00006, ADR 0008), and only
// ever to hmac-sha256 — it can never relabel a row back to sha256. Once no
// legacy row remains — whether because this call converted the last of them
// or because there never were any — it also writes the informational
// chainKeyedSettingKey flag in the same transaction as the re-chain commit
// (never read back as a security gate; see its doc comment). Returns the
// number of rows rewritten.
func (a *Auditor) Rechain(ctx context.Context) (int64, error) {
	const page = 500
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return 0, fmt.Errorf("audit: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return 0, fmt.Errorf("audit: lock: %w", err)
	}
	q := sqlcgen.New(tx)
	legacy, err := q.CountLegacyAuditEvents(ctx)
	if err != nil {
		return 0, err
	}
	var changed int64
	if legacy > 0 {
		oldPrev, newPrev := genesis, genesis
		var after int64
		seenHMAC := false
		for {
			rows, err := q.ListAuditEventsAsc(ctx, sqlcgen.ListAuditEventsAscParams{ID: after, Limit: page})
			if err != nil {
				return 0, err
			}
			for _, ev := range rows {
				if seenHMAC && ev.HashAlg != HashAlgHMAC {
					return 0, fmt.Errorf("%w at id %d; chain not re-keyed", ErrChainBroken, ev.ID)
				}
				if ev.HashAlg == HashAlgHMAC {
					seenHMAC = true
				}
				if !a.rowOK(ev, oldPrev) {
					return 0, fmt.Errorf("%w at id %d; chain not re-keyed", ErrChainBroken, ev.ID)
				}
				canon, _ := canonicalJSON(json.RawMessage(ev.Details))
				h := a.sum(HashAlgHMAC, newPrev, ev.Ts, ev.ActorType, ev.ActorID, ev.Action, ev.ResourceType, ev.ResourceID, ev.OrgID, ev.Ip, canon)
				if ev.HashAlg != HashAlgHMAC || !bytes.Equal(ev.PrevHash, newPrev) || !bytes.Equal(ev.Hash, h) {
					if err := q.UpdateAuditChain(ctx, sqlcgen.UpdateAuditChainParams{ID: ev.ID, PrevHash: newPrev, Hash: h}); err != nil {
						return 0, fmt.Errorf("audit: rechain id %d: %w", ev.ID, err)
					}
					changed++
				}
				oldPrev, newPrev, after = ev.Hash, h, ev.ID
			}
			if len(rows) < page {
				break
			}
		}
	}
	if err := q.UpsertSettingValue(ctx, sqlcgen.UpsertSettingValueParams{Key: chainKeyedSettingKey, Value: []byte("true")}); err != nil {
		return 0, fmt.Errorf("audit: mark %s: %w", chainKeyedSettingKey, err)
	}
	return changed, tx.Commit(ctx)
}

// sum is the chain link: H(prev, ts, actor, action, resource, org, ip,
// canonical details) with H = SHA-256 (legacy) or HMAC-SHA256(key). For
// HashAlgHMAC the algorithm label itself is folded into the MAC input first
// (fix round 1, item 3), so hash_alg cannot be swapped on a row without
// invalidating its hash: the hash commits to which algorithm produced it,
// not just to the fields that algorithm happened to cover. Legacy sha256
// rows keep their original, unprefixed formula unchanged, so Rechain can
// still verify rows written before this field existed.
func (a *Auditor) sum(alg string, prev []byte, ts time.Time, actorType, actorID, action, resourceType, resourceID string,
	orgID *uuid.UUID, ip string, details []byte) []byte {
	var h hash.Hash
	switch alg {
	case HashAlgLegacy:
		h = sha256.New()
	case HashAlgHMAC:
		h = hmac.New(sha256.New, a.key)
		h.Write([]byte(HashAlgHMAC))
		h.Write([]byte{0})
	default:
		return nil
	}
	org := ""
	if orgID != nil {
		org = orgID.String()
	}
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
