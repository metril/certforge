//go:build integration

package settings_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/settings"
)

func envelope(b byte) *crypto.Envelope {
	k := bytes.Repeat([]byte{b}, 32)
	return crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(k), k))
}

func TestSetGet(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	st := settings.NewStore(q, envelope(1))
	if err := st.Set(ctx, "x.y", map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	var out map[string]int
	if err := st.Get(ctx, "x.y", &out); err != nil || out["a"] != 1 {
		t.Fatalf("out %v err %v", out, err)
	}
	if err := st.Get(ctx, "missing", &out); !errors.Is(err, settings.ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestSecretRoundTripAndAtRest(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	st := settings.NewStore(q, envelope(1))
	if err := st.SetSecret(ctx, "smtp.password", []byte("hunter2-hunter2")); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetSecret(ctx, "smtp.password")
	if err != nil || string(got) != "hunter2-hunter2" {
		t.Fatalf("got %q err %v", got, err)
	}
	row, err := q.GetSetting(ctx, "smtp.password")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(row.Secret, []byte("hunter2")) {
		t.Fatal("secret stored in plaintext")
	}
}

func TestSecretWrongKEKNoPanic(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	if err := settings.NewStore(q, envelope(1)).SetSecret(ctx, "k", []byte("v")); err != nil {
		t.Fatal(err)
	}
	_, err := settings.NewStore(q, envelope(2)).GetSecret(ctx, "k")
	if !errors.Is(err, crypto.ErrWrongKEK) {
		t.Fatalf("err = %v, want ErrWrongKEK", err)
	}
}

func TestCanary(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	a := settings.NewStore(q, envelope(1))
	b := settings.NewStore(q, envelope(2))
	if err := a.VerifyCanary(ctx); !errors.Is(err, settings.ErrNotFound) {
		t.Fatalf("fresh verify err = %v", err)
	}
	if err := a.EnsureCanary(ctx); err != nil {
		t.Fatal(err)
	}
	if err := a.EnsureCanary(ctx); err != nil {
		t.Fatal(err)
	}
	if err := b.VerifyCanary(ctx); !errors.Is(err, crypto.ErrWrongKEK) {
		t.Fatalf("wrong kek verify err = %v", err)
	}
	if err := b.EnsureCanary(ctx); !errors.Is(err, crypto.ErrWrongKEK) {
		t.Fatalf("wrong kek ensure err = %v", err)
	}
	if err := a.VerifyCanary(ctx); err != nil {
		t.Fatalf("canary overwritten: %v", err)
	}
}

// TestCanaryNullSecretRowTreatedAsAbsent covers a crypto.canary row that
// exists with a NULL secret (for example a value written at that key by
// some other path before the canary is ever sealed): InsertSettingSecretIfAbsent
// is a key-conflict insert, so an existing row would otherwise block the
// write forever and EnsureCanary would never seal a canary. EnsureCanary
// must treat that row as absent (insert-or-fill), then verify.
func TestCanaryNullSecretRowTreatedAsAbsent(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	if err := q.UpsertSettingValue(ctx, sqlcgen.UpsertSettingValueParams{Key: settings.CanaryKey, Value: json.RawMessage(`null`)}); err != nil {
		t.Fatal(err)
	}
	row, err := q.GetSetting(ctx, settings.CanaryKey)
	if err != nil {
		t.Fatal(err)
	}
	if row.Secret != nil {
		t.Fatalf("fixture row has a secret already: %v", row.Secret)
	}
	st := settings.NewStore(q, envelope(1))
	if err := st.EnsureCanary(ctx); err != nil {
		t.Fatalf("EnsureCanary on a NULL-secret row: %v", err)
	}
	if err := st.VerifyCanary(ctx); err != nil {
		t.Fatalf("verify after fill: %v", err)
	}
}

// TestCanaryConcurrent covers several processes booting at once against a
// fresh database: EnsureCanary's insert-if-absent write means only the
// first one's canary blob lands, and every caller must still come back
// verified rather than erroring or silently overwriting another's blob.
func TestCanaryConcurrent(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	st := settings.NewStore(q, envelope(1))
	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- st.EnsureCanary(ctx)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("EnsureCanary err = %v", err)
		}
	}
	if err := st.VerifyCanary(ctx); err != nil {
		t.Fatalf("verify after concurrent ensure: %v", err)
	}
}

func TestSections(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	st := settings.NewStore(q, envelope(1))
	sec, _ := settings.DefaultRegistry().Section("general")
	raw, stored, err := st.GetSection(ctx, sec)
	if err != nil || string(raw) != "{}" || stored != nil {
		t.Fatalf("default %s stored %s err %v", raw, stored, err)
	}
	if err := st.PutSection(ctx, sec, json.RawMessage(`{"baseUrl":"https://c.example.com"}`)); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSection(ctx, sec, json.RawMessage(`{"baseUrl":"nope"}`)); !errors.Is(err, settings.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	raw, stored, _ = st.GetSection(ctx, sec)
	var v map[string]string
	if err := json.Unmarshal(raw, &v); err != nil || v["baseUrl"] != "https://c.example.com" {
		t.Fatalf("stored %s", raw)
	}
	if string(stored) != string(raw) {
		t.Fatalf("stored %s != value %s once saved", stored, raw)
	}
	var row sqlcgen.Setting
	if row, err = q.GetSetting(ctx, "section.general"); err != nil || row.Key != sec.Key() {
		t.Fatalf("row %v err %v", row.Key, err)
	}
}

func secretSection(t *testing.T) *settings.Section {
	t.Helper()
	r := settings.NewRegistry()
	r.MustRegister("s", json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{
	  "issuer":{"type":"string"},"clientSecret":{"type":"string","secret":true}}}`), json.RawMessage(`{}`))
	sec, _ := r.Section("s")
	return sec
}

func putTx(ctx context.Context, t *testing.T, pool *pgxpool.Pool, st *settings.Store, sec *settings.Section, raw string) ([]string, error) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	changed, err := st.PutSectionTx(ctx, tx, sec, json.RawMessage(raw))
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return changed, nil
}

func TestSectionSecrets(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)
	st := settings.NewStore(q, envelope(1))
	sec := secretSection(t)

	if _, err := putTx(ctx, t, pool, st, sec, `{"issuer":"a","clientSecret":"__unchanged__"}`); !errors.Is(err, settings.ErrUnchangedWithoutStored) {
		t.Fatalf("unchanged with nothing stored: %v", err)
	}
	changed, err := putTx(ctx, t, pool, st, sec, `{"issuer":"a","clientSecret":"s3cret"}`)
	if err != nil || !slices.Equal(changed, []string{"clientSecret"}) {
		t.Fatalf("first set: changed %v err %v", changed, err)
	}
	val, _, err := st.GetSection(ctx, sec)
	if err != nil || strings.Contains(string(val), "s3cret") || strings.Contains(string(val), "clientSecret") {
		t.Fatalf("value leaks secret: %s %v", val, err)
	}
	row, _ := q.GetSetting(ctx, sec.Key())
	if bytes.Contains(row.Secret, []byte("s3cret")) {
		t.Fatal("secret stored in plaintext")
	}
	if changed, err := putTx(ctx, t, pool, st, sec, `{"issuer":"b","clientSecret":"__unchanged__"}`); err != nil || len(changed) != 0 {
		t.Fatalf("unchanged: changed %v err %v", changed, err)
	}
	if m, _ := st.SectionSecrets(ctx, sec); m["clientSecret"] != "s3cret" {
		t.Fatalf("unchanged lost the secret: %v", m)
	}
	if changed, err := putTx(ctx, t, pool, st, sec, `{"issuer":"b","clientSecret":"s3cret"}`); err != nil || len(changed) != 0 {
		t.Fatalf("same value again: changed %v err %v", changed, err)
	}
	if changed, err := putTx(ctx, t, pool, st, sec, `{"issuer":"b"}`); err != nil || len(changed) != 0 {
		t.Fatalf("absent field: changed %v err %v", changed, err)
	}
	if keys, _ := st.StoredSecretKeys(ctx, sec); !slices.Equal(keys, []string{"clientSecret"}) {
		t.Fatalf("absent field must keep the secret: %v", keys)
	}
	if changed, err := putTx(ctx, t, pool, st, sec, `{"issuer":"b","clientSecret":""}`); err != nil || !slices.Equal(changed, []string{"clientSecret"}) {
		t.Fatalf("clear: changed %v err %v", changed, err)
	}
	if keys, _ := st.StoredSecretKeys(ctx, sec); len(keys) != 0 || keys == nil {
		t.Fatalf("empty string must clear, and keys must be an empty slice not nil: %#v", keys)
	}
	if changed, err := putTx(ctx, t, pool, st, sec, `{"issuer":"b","clientSecret":""}`); err != nil || len(changed) != 0 {
		t.Fatalf("clearing an already-clear secret is not a change: changed %v err %v", changed, err)
	}
}

// TestPutSectionTxUpdateCheck covers Section.ValidateUpdate running inside
// PutSectionTx: an AddUpdateCheck function sees nil for a section never
// saved before (first save always allowed), and the section's actual
// previous stored public value on every save after that.
func TestPutSectionTxUpdateCheck(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)
	st := settings.NewStore(q, envelope(1))

	r := settings.NewRegistry()
	r.MustRegister("u", json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{
	  "issuer":{"type":"string"}}}`), json.RawMessage(`{}`))
	if err := r.AddUpdateCheck("u", func(stored, next json.RawMessage) error {
		if stored == nil {
			return nil
		}
		var prev, cur struct {
			Issuer string `json:"issuer"`
		}
		_ = json.Unmarshal(stored, &prev)
		_ = json.Unmarshal(next, &cur)
		if prev.Issuer != cur.Issuer {
			return errors.New("issuer is immutable")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sec, _ := r.Section("u")

	if _, err := putTx(ctx, t, pool, st, sec, `{"issuer":"a"}`); err != nil {
		t.Fatalf("first save: %v", err)
	}
	if _, err := putTx(ctx, t, pool, st, sec, `{"issuer":"a"}`); err != nil {
		t.Fatalf("unchanged issuer: %v", err)
	}
	if _, err := putTx(ctx, t, pool, st, sec, `{"issuer":"b"}`); !errors.Is(err, settings.ErrInvalid) {
		t.Fatalf("changed issuer: err = %v", err)
	}
	raw, _, err := st.GetSection(ctx, sec)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]string
	if err := json.Unmarshal(raw, &v); err != nil || v["issuer"] != "a" {
		t.Fatalf("rejected update must not persist: %s", raw)
	}
}

// TestSectionSecretsFiltersRemovedSchemaKeys covers a secret property that
// used to exist on a section's schema, still sits encrypted in the stored
// blob (nothing deletes it), but was later removed from the schema: it must
// no longer be reported as held.
func TestSectionSecretsFiltersRemovedSchemaKeys(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)
	st := settings.NewStore(q, envelope(1))

	wide := settings.NewRegistry()
	wide.MustRegister("s", json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{
	  "clientSecret":{"type":"string","secret":true},"apiKey":{"type":"string","secret":true}}}`), json.RawMessage(`{}`))
	wideSec, _ := wide.Section("s")
	if _, err := putTx(ctx, t, pool, st, wideSec, `{"clientSecret":"c-val","apiKey":"a-val"}`); err != nil {
		t.Fatal(err)
	}

	narrow := settings.NewRegistry()
	narrow.MustRegister("s", json.RawMessage(`{"type":"object","additionalProperties":false,"properties":{
	  "clientSecret":{"type":"string","secret":true}}}`), json.RawMessage(`{}`))
	narrowSec, _ := narrow.Section("s")

	m, err := st.SectionSecrets(ctx, narrowSec)
	if err != nil || len(m) != 1 || m["clientSecret"] != "c-val" {
		t.Fatalf("SectionSecrets after schema narrowed: %v %v", m, err)
	}
	if keys, err := st.StoredSecretKeys(ctx, narrowSec); err != nil || !slices.Equal(keys, []string{"clientSecret"}) {
		t.Fatalf("StoredSecretKeys after schema narrowed: %v %v", keys, err)
	}
}
