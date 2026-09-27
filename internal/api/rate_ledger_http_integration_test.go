//go:build integration

package api_test

import (
	"net/http"
	"testing"
)

// TestGetRateLedgerMissingCaParam: fix round 1. ca is a required query
// parameter (api/openapi.yaml), so a request that omits it must never reach
// GetRateLedger at all — oapi-codegen's generated wrapper rejects it with a
// RequiredParamError before dispatch, and requestError maps that to 400.
// This is generic parameter-binding behavior shared by every operation with
// a required query parameter, not logic this feature wrote, so (unlike
// TestGetRateLedgerAPI's other cases, which call Server.GetRateLedger
// directly through apiFixture) it needs a real HTTP round trip — that
// generated wrapper sits in front of the handler, not inside it.
func TestGetRateLedgerMissingCaParam(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()
	resp, _ := e.do("GET", "/api/v1/orgs/"+org.String()+"/rate-ledger", nil, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
}
