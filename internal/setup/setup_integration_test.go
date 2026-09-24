//go:build integration

package setup_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/db/dbtest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/setup"
)

var good = setup.Input{AdminPassword: "correct horse battery", OrgName: "Home", OrgSlug: "home", BaseURL: "https://certs.example.com/"}

func TestComplete(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)
	svc := setup.New(pool, audit.New(pool), settings.DefaultRegistry())
	if needs, err := svc.NeedsSetup(ctx); err != nil || !needs {
		t.Fatalf("needs %v err %v", needs, err)
	}
	res, err := svc.Complete(ctx, good)
	if err != nil {
		t.Fatal(err)
	}
	if needs, _ := svc.NeedsSetup(ctx); needs {
		t.Fatal("still needs setup")
	}
	admin, err := q.GetLocalAdmin(ctx)
	if err != nil || admin.ID != res.AdminID {
		t.Fatalf("admin %v err %v", admin.ID, err)
	}
	if ok, _ := authn.VerifyPassword(*admin.LocalPasswordHash, good.AdminPassword); !ok {
		t.Fatal("password not stored")
	}
	rbs, _ := q.ListRoleBindingsForUser(ctx, admin.ID.String())
	if len(rbs) != 1 || rbs[0].Role != "admin" || rbs[0].OrgID != nil {
		t.Fatalf("bindings %+v", rbs)
	}
	org, err := q.GetOrgBySlug(ctx, "home")
	if err != nil || org.ID != res.OrgID {
		t.Fatalf("org %v err %v", org, err)
	}
	row, err := q.GetSetting(ctx, "section.general")
	if err != nil || string(row.Value) != `{"baseUrl": "https://certs.example.com"}` {
		t.Fatalf("general %s err %v", row.Value, err)
	}
	if _, err := svc.Complete(ctx, good); !errors.Is(err, setup.ErrAlreadyComplete) {
		t.Fatalf("second complete err = %v", err)
	}
}

// TestCompleteRevokesPreexistingAdminSessions covers a local admin row that
// survives from an earlier, uncompleted setup attempt (or a restored
// database): Complete overwrites its password, and any session against the
// old one must not remain valid.
func TestCompleteRevokesPreexistingAdminSessions(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)
	hash, err := authn.HashPassword("stale password 12345")
	if err != nil {
		t.Fatal(err)
	}
	u, err := q.CreateLocalAdmin(ctx, hash)
	if err != nil {
		t.Fatal(err)
	}
	sessions := authn.NewSessions(q, authn.DefaultSessionTTL)
	token, _, err := sessions.Create(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	svc := setup.New(pool, audit.New(pool), settings.DefaultRegistry())
	res, err := svc.Complete(ctx, good)
	if err != nil {
		t.Fatal(err)
	}
	if res.AdminID != u.ID {
		t.Fatalf("admin id changed: %v -> %v", u.ID, res.AdminID)
	}
	if _, err := sessions.Lookup(ctx, token); !errors.Is(err, authn.ErrNoSession) {
		t.Fatalf("pre-existing admin's session survived: %v", err)
	}
	admin, err := q.GetLocalAdmin(ctx)
	if err != nil || admin.ID != u.ID {
		t.Fatalf("admin %v err %v", admin.ID, err)
	}
	if ok, _ := authn.VerifyPassword(*admin.LocalPasswordHash, good.AdminPassword); !ok {
		t.Fatal("password not overwritten by Complete")
	}
}

func TestCompleteConcurrent(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	svc := setup.New(pool, audit.New(pool), settings.DefaultRegistry())
	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := svc.Complete(ctx, good)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	ok, already := 0, 0
	for err := range errs {
		switch {
		case err == nil:
			ok++
		case errors.Is(err, setup.ErrAlreadyComplete):
			already++
		default:
			t.Fatalf("unexpected err %v", err)
		}
	}
	if ok != 1 || already != 2 {
		t.Fatalf("ok=%d already=%d", ok, already)
	}
}

func TestCompleteInvalid(t *testing.T) {
	ctx := context.Background()
	pool, _ := dbtest.New(t)
	svc := setup.New(pool, audit.New(pool), settings.DefaultRegistry())
	bad := []setup.Input{
		{AdminPassword: "short", OrgName: "Home", OrgSlug: "home", BaseURL: "https://x.example"},
		{AdminPassword: good.AdminPassword, OrgName: " ", OrgSlug: "home", BaseURL: "https://x.example"},
		{AdminPassword: good.AdminPassword, OrgName: "Home", OrgSlug: "Bad Slug", BaseURL: "https://x.example"},
		{AdminPassword: good.AdminPassword, OrgName: "Home", OrgSlug: "home", BaseURL: "ftp://x"},
		// Passes config.ValidateBaseURL (absolute http(s) URL with a host)
		// but fails the general section schema's "^https?://" pattern,
		// which requires a lowercase scheme.
		{AdminPassword: good.AdminPassword, OrgName: "Home", OrgSlug: "home", BaseURL: "HTTPS://certs.example.com"},
	}
	for i, in := range bad {
		if _, err := svc.Complete(ctx, in); !errors.Is(err, setup.ErrInvalid) {
			t.Fatalf("case %d err = %v", i, err)
		}
	}
	if needs, _ := svc.NeedsSetup(ctx); !needs {
		t.Fatal("invalid input completed setup")
	}
}

func TestSetAdminPassword(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)
	svc := setup.New(pool, audit.New(pool), settings.DefaultRegistry())
	if _, err := svc.Complete(ctx, good); err != nil {
		t.Fatal(err)
	}
	id, err := svc.SetAdminPassword(ctx, "first password 1")
	if err != nil {
		t.Fatal(err)
	}
	sessions := authn.NewSessions(q, authn.DefaultSessionTTL)
	token, _, err := sessions.Create(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err := q.SetUserDisabled(ctx, sqlcgen.SetUserDisabledParams{ID: id, Disabled: true}); err != nil {
		t.Fatal(err)
	}
	id2, err := svc.SetAdminPassword(ctx, "second password 2")
	if err != nil || id2 != id {
		t.Fatalf("id %v -> %v err %v", id, id2, err)
	}
	admin, _ := q.GetLocalAdmin(ctx)
	if ok, _ := authn.VerifyPassword(*admin.LocalPasswordHash, "second password 2"); !ok {
		t.Fatal("password not updated")
	}
	if admin.Disabled {
		t.Fatal("reset did not clear disabled")
	}
	if _, err := sessions.Lookup(ctx, token); !errors.Is(err, authn.ErrNoSession) {
		t.Fatalf("old session survived: %v", err)
	}
	if _, err := svc.SetAdminPassword(ctx, "short"); !errors.Is(err, setup.ErrInvalid) {
		t.Fatalf("short err = %v", err)
	}
}

// TestSetAdminPasswordBeforeSetup covers bootstrap-admin run against a
// database where first-run setup has not completed: it must refuse rather
// than create a local admin outside the setup wizard.
func TestSetAdminPasswordBeforeSetup(t *testing.T) {
	ctx := context.Background()
	pool, q := dbtest.New(t)
	svc := setup.New(pool, audit.New(pool), settings.DefaultRegistry())
	if _, err := svc.SetAdminPassword(ctx, "first password 1"); !errors.Is(err, setup.ErrSetupPending) {
		t.Fatalf("err = %v, want ErrSetupPending", err)
	}
	if _, err := q.GetLocalAdmin(ctx); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("user row created before setup: err = %v", err)
	}
}
