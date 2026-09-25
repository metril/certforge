//go:build integration

package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

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

	// Re-enable: no session revocation, disabled flips back.
	resp, body = e.do(http.MethodPatch, "/api/v1/users/"+victimID.String(), map[string]bool{"disabled": false}, csrf) //nolint:bodyclose // testEnv.doRaw closes the body
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"disabled":false`) {
		t.Fatalf("enable: %d %s", resp.StatusCode, body)
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
