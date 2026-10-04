// Package audit records append-only audit events in a hash chain keyed with
// HMAC-SHA256 (ADR 0008).
package audit

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"log/slog"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/metrics"
)

const lockKey int64 = 0x43460002

// chainKeyedSettingKey records that Rechain has run and no legacy sha256 row
// remained at that point. It is a second, independent gate alongside the
// monotonic per-row rule (fix round 2): an adversary with table-owner access
// can replace the *entire* table contents with a self-consistent,
// legacy-only sha256 chain, in which case no hmac-sha256 row is ever seen
// and the monotonic rule alone lets it through. Reading this flag back and
// failing closed on any sha256 row once it is set closes that gap — unless
// the adversary also deletes the setting row itself, which is why this is a
// mitigation, not a substitute for external head-hash anchoring (ADR 0008,
// still an open known gap).
const chainKeyedSettingKey = "audit.chain_keyed"

// headSettingKey holds the chain head anchor {id, hash, mac}: the newest
// event's id and hash, MACed with the audit key and rewritten by every Record
// in the same transaction as the insert. A walk that ends before the anchor,
// or finds a different hash at its id, means the newest rows were removed
// (ADR 0008). Without the MAC an owner who truncated to N could write a
// matching (N, hash_N) read straight from the table.
const headSettingKey = "audit.head"

// Why a chain failed to verify (VerifyResult.Reason).
const (
	ReasonRowMismatch    = "row_mismatch"
	ReasonDowngrade      = "downgrade"
	ReasonAnchorMissing  = "anchor_missing"
	ReasonAnchorInvalid  = "anchor_invalid"
	ReasonAnchorMismatch = "anchor_mismatch"
	ReasonTailTruncated  = "tail_truncated"
)

type headAnchor struct {
	ID   int64  `json:"id"`
	Hash string `json:"hash"`
	MAC  string `json:"mac"`
}

// ErrChainBroken means a stored event does not match its hash chain.
var ErrChainBroken = errors.New("audit: hash chain broken")

// ErrAuditUnavailable is returned by Record on an Auditor constructed with
// NewDisabled: the KEK canary failed at startup, so the derived audit key
// cannot be trusted. Writing rows under a wrong key would key them so
// neither Rechain nor Check can ever verify them (ADR 0008), so Record
// refuses outright instead. Check and Verify still run (best-effort
// diagnostics over whatever is already in the table).
var ErrAuditUnavailable = errors.New("audit: unavailable (KEK canary failed; recording refused)")

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
	pool     *pgxpool.Pool
	key      []byte
	now      func() time.Time
	disabled bool
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

// NewDisabled returns an Auditor whose Record always fails with
// ErrAuditUnavailable, for a KEK canary failure at startup: key is still
// required (Check/Verify keep working as a best-effort diagnostic over
// whatever is already in the table) but Record refuses to write anything
// under it, since key cannot be trusted to be the real derived audit key.
func NewDisabled(pool *pgxpool.Pool, key []byte) *Auditor {
	if len(key) == 0 {
		panic("audit: NewDisabled called with a nil or empty key")
	}
	return &Auditor{pool: pool, key: key, now: time.Now, disabled: true}
}

// Record appends e to the chain. Appends are serialized by an advisory lock.
func (a *Auditor) Record(ctx context.Context, e Event) error {
	if a.disabled {
		return ErrAuditUnavailable
	}
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
	id, err := q.InsertAuditEvent(ctx, row)
	if err != nil {
		return fmt.Errorf("audit: insert: %w", err)
	}
	if err := a.writeAnchor(ctx, q, id, row.Hash); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	setHead(id)
	return nil
}

var (
	headMu  sync.Mutex
	headMax int64
)

// setHead raises certforge_audit_head_id; a verify that finished before a
// later append must not lower what Record already reported.
func setHead(id int64) {
	headMu.Lock()
	defer headMu.Unlock()
	if id > headMax {
		headMax = id
		metrics.AuditHeadID.Set(float64(id))
	}
}

func (a *Auditor) headMAC(id int64, hash []byte) []byte {
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte("certforge-audit-head\x00"))
	m.Write([]byte(strconv.FormatInt(id, 10)))
	m.Write([]byte{0})
	m.Write(hash)
	return m.Sum(nil)
}

// writeAnchor stores the head anchor for (id, hash). Callers hold the append
// advisory lock inside the transaction q runs in.
func (a *Auditor) writeAnchor(ctx context.Context, q *sqlcgen.Queries, id int64, hash []byte) error {
	b, err := json.Marshal(headAnchor{ID: id, Hash: hex.EncodeToString(hash), MAC: hex.EncodeToString(a.headMAC(id, hash))})
	if err != nil {
		return err
	}
	if err := q.UpsertSettingValue(ctx, sqlcgen.UpsertSettingValueParams{Key: headSettingKey, Value: b}); err != nil {
		return fmt.Errorf("audit: write %s: %w", headSettingKey, err)
	}
	return nil
}

// readAnchor returns the stored anchor; found is false when none exists. A
// stored value that does not parse comes back found with a zero anchor, which
// anchorValid rejects.
func (a *Auditor) readAnchor(ctx context.Context, q *sqlcgen.Queries) (anchor headAnchor, found bool, err error) {
	row, err := q.GetSetting(ctx, headSettingKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return headAnchor{}, false, nil
	}
	if err != nil {
		return headAnchor{}, false, fmt.Errorf("audit: %s: %w", headSettingKey, err)
	}
	if json.Unmarshal(row.Value, &anchor) != nil {
		anchor = headAnchor{}
	}
	return anchor, true, nil
}

// anchorValid reports whether the anchor's MAC matches, and its hash bytes.
func (a *Auditor) anchorValid(an headAnchor) ([]byte, bool) {
	h, err := hex.DecodeString(an.Hash)
	if err != nil {
		return nil, false
	}
	mac, err := hex.DecodeString(an.MAC)
	if err != nil {
		return nil, false
	}
	return h, hmac.Equal(mac, a.headMAC(an.ID, h))
}

// VerifyResult is the outcome of walking the chain.
type VerifyResult struct {
	OK         bool
	Count      int64  // rows that verified
	BrokenAtID int64  // first bad row when !OK; 0 when no row is to blame
	HeadHash   []byte // hash of the last good row
	HeadID     int64  // id of the last good row; 0 for an empty chain
	AnchorID   int64  // id the stored head anchor points at; 0 when there is none
	Reason     string // Reason* constant when !OK
}

// Check walks the whole chain. A mismatch is a result, not an error. Two
// downgrade gates apply, either of which is enough to reject a sha256 row:
// the monotonic rule (once a hmac-sha256 row has been seen in chain order,
// no later row may be sha256 — catches a forged row appended after
// re-keying) and, independently, chainKeyedSettingKey read up front (once
// Rechain has run, ANY sha256 row is rejected even if no hmac-sha256 row is
// reachable at all — catches an owner-access adversary who replaced the
// whole table with a self-consistent legacy-only chain, which the monotonic
// rule alone cannot see; fix round 2). Either way tampering can forge a
// legacy-formula hash without the key, so a row's own internal consistency
// proves nothing once the chain is known to have been keyed.
func (a *Auditor) Check(ctx context.Context) (VerifyResult, error) {
	const page = 500
	q := sqlcgen.New(a.pool)
	keyed, err := a.chainKeyed(ctx, q)
	if err != nil {
		return VerifyResult{}, err
	}
	// The anchor is read before the walk so appends need not be blocked: a
	// row written meanwhile is simply past it.
	anchor, haveAnchor, err := a.readAnchor(ctx, q)
	if err != nil {
		return VerifyResult{}, err
	}
	res := VerifyResult{OK: true, HeadHash: genesis}
	var anchorHash []byte
	if haveAnchor {
		res.AnchorID = anchor.ID
		var ok bool
		if anchorHash, ok = a.anchorValid(anchor); !ok {
			res.OK, res.Reason = false, ReasonAnchorInvalid
			return res, nil
		}
	}
	prev := genesis
	var after int64
	seenHMAC, anchorSeen := false, false
	for {
		rows, err := q.ListAuditEventsAsc(ctx, sqlcgen.ListAuditEventsAscParams{ID: after, Limit: page})
		if err != nil {
			return res, err
		}
		for _, ev := range rows {
			if (keyed || seenHMAC) && ev.HashAlg != HashAlgHMAC {
				res.OK, res.BrokenAtID, res.Reason = false, ev.ID, ReasonDowngrade
				return res, nil
			}
			if ev.HashAlg == HashAlgHMAC {
				seenHMAC = true
			}
			if !a.rowOK(ev, prev) {
				res.OK, res.BrokenAtID, res.Reason = false, ev.ID, ReasonRowMismatch
				return res, nil
			}
			if haveAnchor && ev.ID == anchor.ID {
				anchorSeen = true
				if !bytes.Equal(ev.Hash, anchorHash) {
					res.OK, res.BrokenAtID, res.Reason = false, ev.ID, ReasonAnchorMismatch
					return res, nil
				}
			}
			prev, after, res.HeadHash, res.HeadID = ev.Hash, ev.ID, ev.Hash, ev.ID
			res.Count++
		}
		if len(rows) < page {
			break
		}
	}
	switch {
	case haveAnchor && !anchorSeen:
		res.OK, res.BrokenAtID, res.Reason = false, res.HeadID+1, ReasonTailTruncated
	case !haveAnchor && res.Count > 0 && (keyed || seenHMAC):
		res.OK, res.Reason = false, ReasonAnchorMissing
	}
	if res.HeadID > 0 {
		setHead(res.HeadID)
		slog.Info("audit chain verified", "ok", res.OK, "headId", res.HeadID, "headHash", hex.EncodeToString(res.HeadHash)[:16])
	}
	return res, nil
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

// chainKeyed reports whether chainKeyedSettingKey is set.
func (a *Auditor) chainKeyed(ctx context.Context, q *sqlcgen.Queries) (bool, error) {
	row, err := q.GetSetting(ctx, chainKeyedSettingKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("audit: %s: %w", chainKeyedSettingKey, err)
	}
	var v bool
	if err := json.Unmarshal(row.Value, &v); err != nil {
		return false, fmt.Errorf("audit: %s: %w", chainKeyedSettingKey, err)
	}
	return v, nil
}

// Rechain converts the chain to HMAC-SHA256 once, under the append advisory
// lock. Two gates run before it rewrites anything: chainKeyedSettingKey is
// read first — if the chain was already keyed, any legacy row still present
// means the table was tampered with wholesale (fix round 2: an owner-access
// adversary can replace the entire table with a self-consistent legacy-only
// chain, which the monotonic per-row rule below cannot see since it never
// encounters a hmac-sha256 row to trip on), and Rechain refuses outright,
// rewriting nothing. Otherwise every row is verified with its stored
// algorithm, subject to the same monotonic downgrade gate as Check (once a
// hmac-sha256 row has been seen mid-walk, a later sha256 row is refused
// rather than laundered into a freshly-rewritten valid HMAC row); any check
// failure leaves nothing changed and returns ErrChainBroken. It does not
// disable the append-only trigger (that would need table ownership); the
// trigger itself allows the three-column update Rechain performs (migration
// 00006, ADR 0008), and only ever to hmac-sha256 — it can never relabel a
// row back to sha256. Once no legacy row remains — whether because this
// call converted the last of them or because there never were any — it also
// writes chainKeyedSettingKey in the same transaction as the re-chain
// commit. Returns the number of rows rewritten.
func (a *Auditor) Rechain(ctx context.Context) (int64, error) {
	if a.disabled {
		// Belt and braces: serve already skips this call outright when the
		// KEK canary failed (its own gate), but a disabled Auditor refuses
		// here too rather than relying solely on the caller remembering not
		// to invoke it.
		return 0, ErrAuditUnavailable
	}
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
	keyed, err := a.chainKeyed(ctx, q)
	if err != nil {
		return 0, err
	}
	legacy, err := q.CountLegacyAuditEvents(ctx)
	if err != nil {
		return 0, err
	}
	if keyed && legacy > 0 {
		return 0, fmt.Errorf("%w: chain already keyed but %d legacy row(s) present; refusing to rewrite", ErrChainBroken, legacy)
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
	// Rewritten hashes invalidate the anchor, and an install upgraded from
	// before the anchor existed has rows but none. An anchor that is present
	// and untouched is left alone, so a restart never re-anchors over a
	// truncation that Check should report.
	_, haveAnchor, err := a.readAnchor(ctx, q)
	if err != nil {
		return 0, err
	}
	head := int64(0)
	if changed > 0 || !haveAnchor {
		last, err := q.LastAuditEvent(ctx)
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("audit: last event: %w", err)
		}
		if err == nil {
			if err := a.writeAnchor(ctx, q, last.ID, last.Hash); err != nil {
				return 0, err
			}
			head = last.ID
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return 0, err
	}
	if head > 0 {
		setHead(head)
	}
	return changed, nil
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
