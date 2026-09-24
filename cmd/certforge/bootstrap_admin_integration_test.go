//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/setup"
)

func TestBootstrapAdmin(t *testing.T) {
	url := dbtest.URL(t)
	t.Setenv("CF_DATABASE_URL", url)
	t.Setenv("CF_KEK", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)))
	t.Setenv("CF_KEK_FILE", "")
	t.Setenv("CF_ADMIN_PASSWORD", "")

	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"bootstrap-admin"}, &out, &errOut); code != 1 {
		t.Fatalf("missing password code %d", code)
	}

	// Before first-run setup completes, bootstrap-admin must refuse: no
	// local admin may be created outside the setup wizard.
	stdin = strings.NewReader("stdin password 123\n")
	errOut.Reset()
	if code := run(context.Background(), []string{"bootstrap-admin", "--password-stdin"}, &out, &errOut); code != 1 {
		t.Fatalf("pre-setup code %d out %s", code, errOut.String())
	}
	if !strings.Contains(errOut.String(), "setup") {
		t.Fatalf("errOut %q, want a setup-pending message", errOut.String())
	}

	ctx := context.Background()
	pool, err := db.Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := sqlcgen.New(pool).GetLocalAdmin(ctx); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("admin row created before setup completed: err = %v", err)
	}

	svc := setup.New(pool, audit.New(pool), settings.DefaultRegistry())
	in := setup.Input{AdminPassword: "initial password ok", OrgName: "Home", OrgSlug: "home", BaseURL: "https://certs.example.com"}
	if _, err := svc.Complete(ctx, in); err != nil {
		t.Fatal(err)
	}

	stdin = strings.NewReader("stdin password 123\n")
	defer func() { stdin = nil }()
	out.Reset()
	if code := run(context.Background(), []string{"bootstrap-admin", "--password-stdin"}, &out, &errOut); code != 0 {
		t.Fatalf("code %d stderr %s", code, errOut.String())
	}
	if !strings.Contains(out.String(), "password set") {
		t.Fatalf("out %q", out.String())
	}

	admin, err := sqlcgen.New(pool).GetLocalAdmin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := authn.VerifyPassword(*admin.LocalPasswordHash, "stdin password 123"); !ok {
		t.Fatal("password not set")
	}
}
