package client_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/client"
)

// TestClientGenerated is a compile-time and smoke-test proof that the
// generated client (api/oapi-codegen.client.yaml, Task 2) exposes
// ClientWithResponses / NewClientWithResponses (Go names table) with
// methods for two representative Phase 6A operations: GetServerInfoWithResponse
// (no path/query parameters) and ListEventsWithResponse (an org path
// parameter and query filters). If either operation stopped being declared
// in api/openapi.yaml, or the generated method signature changed, this
// file would fail to build.
func TestClientGenerated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/server-info":
			_ = json.NewEncoder(w).Encode(map[string]string{"version": "test"})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"items": []any{}, "nextCursor": nil})
		}
	}))
	defer srv.Close()

	c, err := client.NewClientWithResponses(srv.URL)
	if err != nil {
		t.Fatal(err)
	}

	infoResp, err := c.GetServerInfoWithResponse(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if infoResp.StatusCode() != http.StatusOK || infoResp.JSON200 == nil || infoResp.JSON200.Version != "test" {
		t.Fatalf("GetServerInfoWithResponse: status %d, body %s", infoResp.StatusCode(), infoResp.Body)
	}

	eventsResp, err := c.ListEventsWithResponse(context.Background(), uuid.New(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if eventsResp.StatusCode() != http.StatusOK || eventsResp.JSON200 == nil {
		t.Fatalf("ListEventsWithResponse: status %d, body %s", eventsResp.StatusCode(), eventsResp.Body)
	}
}
