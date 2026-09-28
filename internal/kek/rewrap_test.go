package kek

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/settings"
)

func testKey(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }

// fakeStore is an in-memory Store: real crypto.KeyWrapper values do the
// actual sealing, but nothing here touches Postgres, so these tests cover
// the paging/counting/race algorithm on its own (Review Focus, T5).
type fakeStore struct {
	rows map[RewrapTable]map[string]map[string][]byte
	seq  map[RewrapTable][]string

	// raceOnce, keyed "table|pk|col", mutates that column to a given value
	// the first time CAS is called for it — before the normal compare —
	// simulating a concurrent writer landing between this run's Page and
	// CAS calls: the compare then fails against the now-stale old value,
	// exactly like a real lost race would (TestRewrapCASLosesRaceSafely).
	raceOnce map[string][]byte
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		rows: map[RewrapTable]map[string]map[string][]byte{}, seq: map[RewrapTable][]string{},
		raceOnce: map[string][]byte{},
	}
}

func (f *fakeStore) put(table RewrapTable, pk, col string, val []byte) {
	if f.rows[table] == nil {
		f.rows[table] = map[string]map[string][]byte{}
	}
	if f.rows[table][pk] == nil {
		f.rows[table][pk] = map[string][]byte{}
		f.seq[table] = append(f.seq[table], pk)
	}
	f.rows[table][pk][col] = val
}

func (f *fakeStore) Canary(context.Context) (Row, bool, error) {
	cols, ok := f.rows[TableSettings][settings.CanaryKey]
	if !ok {
		return Row{}, false, nil
	}
	return Row{PK: settings.CanaryKey, Cols: cloneCols(cols)}, true, nil
}

func (f *fakeStore) Page(_ context.Context, table RewrapTable, after string, limit int32) ([]Row, error) {
	pks := append([]string(nil), f.seq[table]...)
	sort.Strings(pks)
	var out []Row
	for _, pk := range pks {
		if pk <= after {
			continue
		}
		out = append(out, Row{PK: pk, Cols: cloneCols(f.rows[table][pk])})
		if int32(len(out)) >= limit {
			break
		}
	}
	return out, nil
}

func (f *fakeStore) CAS(_ context.Context, table RewrapTable, pk, col string, old, newVal []byte) (bool, error) {
	key := fmt.Sprintf("%s|%s|%s", table, pk, col)
	if race, ok := f.raceOnce[key]; ok {
		delete(f.raceOnce, key)
		f.rows[table][pk][col] = race
	}
	if !bytes.Equal(f.rows[table][pk][col], old) {
		return false, nil
	}
	f.rows[table][pk][col] = newVal
	return true, nil
}

func cloneCols(cols map[string][]byte) map[string][]byte {
	cp := make(map[string][]byte, len(cols))
	for k, v := range cols {
		cp[k] = append([]byte(nil), v...)
	}
	return cp
}

// seal returns raw bytes for plaintext sealed under w, as they would be
// stored in a bytea column.
func seal(t *testing.T, w crypto.KeyWrapper, plaintext string) []byte {
	t.Helper()
	b, err := crypto.NewEnvelope(w).Encrypt(context.Background(), []byte(plaintext))
	if err != nil {
		t.Fatal(err)
	}
	return b.Marshal()
}

func testEnv() (active, prev crypto.KeyWrapper, env *crypto.Envelope) {
	activeKey, prevKey := testKey(1), testKey(2)
	active = crypto.NewStaticWrapper(crypto.KeyID(activeKey), activeKey)
	prev = crypto.NewStaticWrapper(crypto.KeyID(prevKey), prevKey)
	return active, prev, crypto.NewEnvelope(active, prev)
}

// TestRewrapPagesAndCounts covers a fake store with 450 rows over 2 KEKs
// (PageSize 200, so 3 pages): rows under the previous KEK are rewrapped,
// rows already under the active one are left alone, and Scanned/Rewrapped
// match exactly with no lost races.
func TestRewrapPagesAndCounts(t *testing.T) {
	active, prev, env := testEnv()
	store := newFakeStore()

	const total = 450
	const underPrevious = 300
	for i := 0; i < total; i++ {
		pk := uuid.New().String()
		var raw []byte
		if i < underPrevious {
			raw = seal(t, prev, fmt.Sprintf("secret-%d", i))
		} else {
			raw = seal(t, active, fmt.Sprintf("secret-%d", i))
		}
		store.put(TableCertificateVersions, pk, "private_key", raw)
	}

	svc := &Service{Env: env, Info: Info{Kind: "static", KEKID: active.ID()}, store: store}
	status, err := svc.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ts := tableStatus(t, status, TableCertificateVersions)
	if ts.Scanned != total {
		t.Fatalf("scanned = %d, want %d", ts.Scanned, total)
	}
	if ts.Rewrapped != underPrevious {
		t.Fatalf("rewrapped = %d, want %d", ts.Rewrapped, underPrevious)
	}
	if ts.Remaining != 0 {
		t.Fatalf("remaining = %d, want 0", ts.Remaining)
	}

	// Every row now decrypts under the active KEK alone.
	for _, pk := range store.seq[TableCertificateVersions] {
		var b crypto.Blob
		if err := b.Unmarshal(store.rows[TableCertificateVersions][pk]["private_key"]); err != nil {
			t.Fatal(err)
		}
		if b.KEKID != active.ID() {
			t.Fatalf("row %s still sealed under %q", pk, b.KEKID)
		}
	}
}

// TestRewrapCASLosesRaceSafely covers a concurrent writer landing between
// this run's Page and CAS calls: the write it made is kept (never
// clobbered), the row is counted in remaining on this run, and a second run
// (no more injected race) finds it again and finishes the job, remaining 0.
func TestRewrapCASLosesRaceSafely(t *testing.T) {
	active, prev, env := testEnv()
	store := newFakeStore()

	pk := uuid.New().String()
	store.put(TableCertificateVersions, pk, "private_key", seal(t, prev, "original"))
	// The racer's write is itself still sealed under the previous KEK (a
	// realistic concurrent write elsewhere using the same active envelope's
	// previous wrapper would not do this, but it lets the CAS legitimately
	// fail while leaving the row still needing a rewrap for run 2).
	raceValue := seal(t, prev, "raced-in-concurrently")
	store.raceOnce[fmt.Sprintf("%s|%s|private_key", TableCertificateVersions, pk)] = raceValue

	svc := &Service{Env: env, Info: Info{Kind: "static", KEKID: active.ID()}, store: store}
	status, err := svc.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ts := tableStatus(t, status, TableCertificateVersions)
	if ts.Remaining != 1 {
		t.Fatalf("remaining after race = %d, want 1", ts.Remaining)
	}
	if !bytes.Equal(store.rows[TableCertificateVersions][pk]["private_key"], raceValue) {
		t.Fatal("the concurrent writer's value was overwritten instead of kept")
	}

	// Second run: no more injected race, the row (still previous-sealed)
	// is picked up cleanly.
	status2, err := svc.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ts2 := tableStatus(t, status2, TableCertificateVersions)
	if ts2.Remaining != 0 || ts2.Rewrapped != 1 {
		t.Fatalf("second run: remaining=%d rewrapped=%d, want 0/1", ts2.Remaining, ts2.Rewrapped)
	}
}

// TestRewrapCanaryFirstFailsFast covers a canary sealed under a KEK id that
// matches neither the active nor any previous wrapper: run fails
// immediately on the canary check, before ever touching the main tables.
func TestRewrapCanaryFirstFailsFast(t *testing.T) {
	active, _, env := testEnv()
	store := newFakeStore()

	unknownKey := testKey(9)
	unknown := crypto.NewStaticWrapper(crypto.KeyID(unknownKey), unknownKey)
	store.put(TableSettings, settings.CanaryKey, "secret", seal(t, unknown, "canary"))

	// A row elsewhere, decryptable, that a full run would otherwise rewrap.
	otherPK := uuid.New().String()
	_, prev, _ := testEnv()
	store.put(TableCertificateVersions, otherPK, "private_key", seal(t, prev, "x"))

	svc := &Service{Env: env, Info: Info{Kind: "static", KEKID: active.ID()}, store: store}
	status, err := svc.run(context.Background())
	if err == nil || !errors.Is(err, crypto.ErrWrongKEK) {
		t.Fatalf("err = %v, want crypto.ErrWrongKEK", err)
	}
	if status.Running {
		t.Fatal("status still marked running after a failed run")
	}
	if status.Error == "" {
		t.Fatal("status.Error not set")
	}
	// A failed run must not report remaining=0: the operations runbook
	// reads that as "safe to drop CF_KEK_PREVIOUS". otherPK is still
	// sealed under prev (never reached — the canary check failed before
	// any table was scanned), so a read-only recount over every table must
	// still find it.
	if status.Remaining == 0 {
		t.Fatal("status.Remaining = 0 on a failed run, want > 0")
	}
	for _, ts := range status.Tables {
		if ts.Scanned != 0 {
			t.Fatalf("table %s was scanned (%d rows) after the canary check failed fast", ts.Table, ts.Scanned)
		}
	}
	// The other row was never touched: still sealed under prev, not active.
	var b crypto.Blob
	if err := b.Unmarshal(store.rows[TableCertificateVersions][otherPK]["private_key"]); err != nil {
		t.Fatal(err)
	}
	if b.KEKID != prev.ID() {
		t.Fatal("a table row was rewritten even though the canary-first check failed")
	}
}

func tableStatus(t *testing.T, status *RewrapStatus, table RewrapTable) TableStatus {
	t.Helper()
	for _, ts := range status.Tables {
		if ts.Table == table {
			return ts
		}
	}
	t.Fatalf("no status for table %s", table)
	return TableStatus{}
}

// TestRewrapWorkerNowOverride confirms Service.Now, when set, is what
// RewrapStatus.StartedAt uses (deterministic status for callers that poll
// it), not time.Now.
func TestRewrapWorkerNowOverride(t *testing.T) {
	active, _, env := testEnv()
	fixed := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	svc := &Service{Env: env, Info: Info{Kind: "static", KEKID: active.ID()}, store: newFakeStore(), Now: func() time.Time { return fixed }}
	status, err := svc.run(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !status.StartedAt.Equal(fixed) {
		t.Fatalf("StartedAt = %v, want %v", status.StartedAt, fixed)
	}
}
