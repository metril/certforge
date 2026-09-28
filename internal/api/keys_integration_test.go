//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/riverqueue/river"
	"github.com/riverqueue/river/rivertype"

	"github.com/metril/certforge/internal/api"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/kek"
)

// fakeKekInserter stands in for the real river client: the first InsertTx
// call succeeds, every later one reports UniqueSkippedAsDuplicate, the same
// shape river itself reports for RewrapArgs.InsertOpts' uniqueness — enough
// to exercise startRewrap's 202/409 split without a real river worker
// running the job.
type fakeKekInserter struct{ queued bool }

func (f *fakeKekInserter) InsertTx(_ context.Context, _ pgx.Tx, _ river.JobArgs, _ *river.InsertOpts) (*rivertype.JobInsertResult, error) {
	dup := f.queued
	f.queued = true
	return &rivertype.JobInsertResult{Job: &rivertype.JobRow{}, UniqueSkippedAsDuplicate: dup}, nil
}

func newKeysTestEnv(t *testing.T) *testEnv {
	var keysSvc *kek.Service
	e := newTestEnvOpts(t, func(d *api.Deps) {
		keysSvc = &kek.Service{
			Settings: d.Settings, Pool: d.Pool, Audit: d.Auditor, River: &fakeKekInserter{},
			Info: kek.Info{Kind: "static", KEKID: "static-test0000"},
		}
		d.Keys = keysSvc
	})
	return e
}

// TestKeysStatusAndStartRewrap covers GET /keys/status and POST
// /keys/rewrap: settings:read/settings:write are required, a rewrap starts
// with 202 and is audited kek.rewrap_started, and a second call while it is
// still queued answers 409.
func TestKeysStatusAndStartRewrap(t *testing.T) {
	e := newKeysTestEnv(t)
	csrf, _ := e.seedAdminSession()

	resp, body := e.do(http.MethodGet, "/api/v1/keys/status", nil, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	var st gen.KeysStatus
	if err := json.Unmarshal(body, &st); err != nil {
		t.Fatal(err)
	}
	if st.KekId != "static-test0000" || string(st.Kind) != "static" {
		t.Fatalf("status = %+v", st)
	}
	if st.Rewrap != nil {
		t.Fatalf("rewrap should be nil before any run: %+v", st.Rewrap)
	}

	resp2, body2 := e.do(http.MethodPost, "/api/v1/keys/rewrap", nil, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp2.StatusCode != http.StatusAccepted {
		t.Fatalf("start status = %d, body %s", resp2.StatusCode, body2)
	}

	resp3, body3 := e.do(http.MethodPost, "/api/v1/keys/rewrap", nil, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp3.StatusCode != http.StatusConflict {
		t.Fatalf("second start status = %d, body %s", resp3.StatusCode, body3)
	}

	ctx := context.Background()
	rows, err := e.deps.Queries.ListAuditEvents(ctx, sqlcgen.ListAuditEventsParams{Action: "kek.rewrap_started", AnyOrg: true, PageLimit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("kek.rewrap_started audit rows = %d, want 1", len(rows))
	}
}

// TestKeysRewrapRequiresSettingsWrite covers a viewer (settings:read but
// not settings:write) getting 403 from POST /keys/rewrap while GET
// /keys/status still succeeds.
func TestKeysRewrapRequiresSettingsWrite(t *testing.T) {
	e := newKeysTestEnv(t)
	client, csrf, _ := e.userSession("viewer1", authz.RoleViewer, nil)

	resp, body := e.doClient(client, http.MethodGet, "/api/v1/keys/status", nil, http.Header{"X-CSRF-Token": {csrf}}) //nolint:bodyclose // doClient closes the body
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}

	resp2, body2 := e.doClient(client, http.MethodPost, "/api/v1/keys/rewrap", nil, http.Header{"X-CSRF-Token": {csrf}}) //nolint:bodyclose // doClient closes the body
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("start status = %d, body %s", resp2.StatusCode, body2)
	}
}
