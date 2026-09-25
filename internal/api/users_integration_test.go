//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// lastAuditDetails returns the details column (as raw JSON text) of the most
// recent event matching action and resourceID.
func lastAuditDetails(t *testing.T, e *testEnv, action, resourceID string) string {
	t.Helper()
	var details string
	if err := e.deps.Pool.QueryRow(context.Background(),
		`SELECT details::text FROM audit_events WHERE action = $1 AND resource_id = $2 ORDER BY id DESC LIMIT 1`,
		action, resourceID).Scan(&details); err != nil {
		t.Fatalf("audit %s for %s: %v", action, resourceID, err)
	}
	return details
}

// auditCount counts every event matching action and resourceID.
func auditCount(t *testing.T, e *testEnv, action, resourceID string) int {
	t.Helper()
	var n int
	if err := e.deps.Pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_events WHERE action = $1 AND resource_id = $2`, action, resourceID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestUsers(t *testing.T) {
	e := newTestEnv(t)
	csrf, org := e.seedAdminSession()
	orgAdmin, oaCSRF, _ := e.userSession("olga", "org-admin", &org)
	victim, _, victimID := e.userSession("vic", "viewer", &org)

	resp, body := e.doClient(orgAdmin, http.MethodGet, "/api/v1/users", nil, nil) //nolint:bodyclose // doClient closes the body
	var list struct {
		Items []struct {
			DisplayName string `json:"displayName"`
			LocalAdmin  bool   `json:"localAdmin"`
		} `json:"items"`
	}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(body, &list) != nil || len(list.Items) != 3 {
		t.Fatalf("org-admin list: %d %s", resp.StatusCode, body)
	}
	lower := strings.ToLower(string(body))
	if strings.Contains(lower, "password") || strings.Contains(lower, "hash") {
		t.Fatalf("user list body leaks a credential field: %s", body)
	}

	hdr := http.Header{"X-Csrf-Token": {oaCSRF}}
	if resp, _ := e.doClient(orgAdmin, http.MethodPatch, "/api/v1/users/"+victimID.String(), map[string]bool{"disabled": true}, hdr); resp.StatusCode != http.StatusForbidden { //nolint:bodyclose // doClient closes the body
		t.Fatalf("org-admin disable: %d", resp.StatusCode)
	}
	resp, body = e.do(http.MethodPatch, "/api/v1/users/"+victimID.String(), map[string]bool{"disabled": true}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"disabled":true`) {
		t.Fatalf("disable: %d %s", resp.StatusCode, body)
	}
	if resp, _ := e.doClient(victim, http.MethodGet, "/api/v1/auth/me", nil, nil); resp.StatusCode != http.StatusUnauthorized { //nolint:bodyclose // doClient closes the body
		t.Fatalf("disabled user's session: %d", resp.StatusCode)
	}
	var sessions int
	if err := e.deps.Pool.QueryRow(context.Background(), `SELECT count(*) FROM sessions WHERE user_id = $1`, victimID).Scan(&sessions); err != nil || sessions != 0 {
		t.Fatalf("sessions left %d %v", sessions, err)
	}

	vid := victimID.String()
	if d := lastAuditDetails(t, e, "user.update", vid); !strings.Contains(d, `"before": {"disabled": false}`) || !strings.Contains(d, `"after": {"disabled": true}`) {
		t.Fatalf("disable user.update audit details: %s", d)
	}
	if d := lastAuditDetails(t, e, "session.revoked", vid); !strings.Contains(d, `"count": 1`) || !strings.Contains(d, `"reason": "user_disabled"`) {
		t.Fatalf("session.revoked audit details: %s", d)
	}

	// Re-enable: no session revocation, disabled flips back.
	resp, body = e.do(http.MethodPatch, "/api/v1/users/"+victimID.String(), map[string]bool{"disabled": false}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"disabled":false`) {
		t.Fatalf("enable: %d %s", resp.StatusCode, body)
	}
	if d := lastAuditDetails(t, e, "user.update", vid); !strings.Contains(d, `"before": {"disabled": true}`) || !strings.Contains(d, `"after": {"disabled": false}`) {
		t.Fatalf("enable user.update audit details: %s", d)
	}
	if n := auditCount(t, e, "session.revoked", vid); n != 1 {
		t.Fatalf("expected exactly one session.revoked event (from disable only), got %d", n)
	}
}

func TestUserCannotDisableSelf(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	_, body := e.do(http.MethodGet, "/api/v1/auth/me", nil, "") //nolint:bodyclose // testEnv.doRaw closes the body
	var me struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	_ = json.Unmarshal(body, &me)
	if resp, _ := e.do(http.MethodPatch, "/api/v1/users/"+me.User.ID, map[string]bool{"disabled": true}, csrf); resp.StatusCode != http.StatusConflict { //nolint:bodyclose // testEnv.doRaw closes the body
		t.Fatalf("self-disable: %d", resp.StatusCode)
	}
}

// TestUserDisableUnknownReturns404 covers the 404 branch of updateUser.
func TestUserDisableUnknownReturns404(t *testing.T) {
	e := newTestEnv(t)
	csrf, _ := e.seedAdminSession()
	resp, _ := e.do(http.MethodPatch, "/api/v1/users/00000000-0000-0000-0000-000000000000", map[string]bool{"disabled": true}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown user disable: %d", resp.StatusCode)
	}
}
