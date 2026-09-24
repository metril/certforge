//go:build integration

package settings_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

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

func TestSections(t *testing.T) {
	ctx := context.Background()
	_, q := dbtest.New(t)
	st := settings.NewStore(q, envelope(1))
	sec, _ := settings.DefaultRegistry().Section("general")
	raw, err := st.GetSection(ctx, sec)
	if err != nil || string(raw) != "{}" {
		t.Fatalf("default %s err %v", raw, err)
	}
	if err := st.PutSection(ctx, sec, json.RawMessage(`{"baseUrl":"https://c.example.com"}`)); err != nil {
		t.Fatal(err)
	}
	if err := st.PutSection(ctx, sec, json.RawMessage(`{"baseUrl":"nope"}`)); !errors.Is(err, settings.ErrInvalid) {
		t.Fatalf("err = %v", err)
	}
	raw, _ = st.GetSection(ctx, sec)
	var v map[string]string
	if err := json.Unmarshal(raw, &v); err != nil || v["baseUrl"] != "https://c.example.com" {
		t.Fatalf("stored %s", raw)
	}
	var row sqlcgen.Setting
	if row, err = q.GetSetting(ctx, "section.general"); err != nil || row.Key != sec.Key() {
		t.Fatalf("row %v err %v", row.Key, err)
	}
}
