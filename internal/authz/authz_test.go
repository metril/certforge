package authz

import (
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/authn"
)

func principal(role string, org *uuid.UUID) authn.Principal {
	return authn.Principal{Kind: authn.KindUser, Bindings: []authn.Binding{{Role: role, OrgID: org}}}
}

func TestCan(t *testing.T) {
	org1, org2 := uuid.New(), uuid.New()
	admin := principal(RoleAdmin, nil)
	orgAdmin := principal(RoleOrgAdmin, &org1)
	operator := principal(RoleOperator, &org1)
	viewer := principal(RoleViewer, &org1)
	auditor := principal(RoleAuditor, &org1)
	agent := admin
	agent.Kind = authn.KindAgent
	none := authn.Principal{Kind: authn.KindUser}
	globalViewer := principal(RoleViewer, nil)
	globalOperator := principal(RoleOperator, nil)
	unknownRole := principal("nobody", &org1)
	apiKeyAdmin := principal(RoleAdmin, nil)
	apiKeyAdmin.Kind = authn.KindAPIKey
	apiKeyAdmin.APIKey = &authn.APIKeyInfo{Scopes: []string{"admin"}}
	readKey := principal(RoleAdmin, nil)
	readKey.Kind = authn.KindAPIKey
	readKey.APIKey = &authn.APIKeyInfo{Scopes: []string{"certs:read"}, OrgID: &org1}
	boundKey := principal(RoleAdmin, nil)
	boundKey.Kind = authn.KindAPIKey
	boundKey.APIKey = &authn.APIKeyInfo{Scopes: []string{"certs:read", "certs:write"}, Bindings: []authn.Binding{{Role: RoleViewer, OrgID: &org1}}}
	bareKey := principal(RoleAdmin, nil)
	bareKey.Kind = authn.KindAPIKey
	multiBinding := authn.Principal{Kind: authn.KindUser, Bindings: []authn.Binding{
		{Role: RoleViewer, OrgID: &org1},
		{Role: RoleOperator, OrgID: &org2},
	}}
	cases := []struct {
		name   string
		p      authn.Principal
		action Action
		org    *uuid.UUID
		want   bool
	}{
		{"admin settings write", admin, ActionSettingsWrite, nil, true},
		{"admin keys export", admin, ActionKeysExport, &org1, true},
		{"org-admin certs write own", orgAdmin, ActionCertsWrite, &org1, true},
		{"org-admin certs write other", orgAdmin, ActionCertsWrite, &org2, false},
		{"org-admin settings write", orgAdmin, ActionSettingsWrite, nil, false},
		{"org-admin cas write", orgAdmin, ActionCAsWrite, nil, false},
		{"org-admin keys export", orgAdmin, ActionKeysExport, &org1, false},
		{"org-admin shared cas read", orgAdmin, ActionCAsRead, nil, true},
		{"org-admin certs read global", orgAdmin, ActionCertsRead, nil, false},
		{"operator issue", operator, ActionCertsIssue, &org1, true},
		{"operator users write", operator, ActionUsersWrite, &org1, false},
		{"viewer read", viewer, ActionCertsRead, &org1, true},
		{"viewer write", viewer, ActionCertsWrite, &org1, false},
		{"viewer audit", viewer, ActionAuditRead, &org1, false},
		{"auditor audit", auditor, ActionAuditRead, &org1, true},
		{"agent denied", agent, ActionCertsRead, &org1, false},
		{"no bindings", none, ActionOrgsRead, nil, false},
		{"global viewer certs write global", globalViewer, ActionCertsWrite, nil, false},
		{"global viewer certs write org", globalViewer, ActionCertsWrite, &org1, false},
		{"global viewer keys export", globalViewer, ActionKeysExport, nil, false},
		{"global operator settings write", globalOperator, ActionSettingsWrite, nil, false},
		{"global viewer certs read other org", globalViewer, ActionCertsRead, &org2, true},
		{"unknown role certs read", unknownRole, ActionCertsRead, &org1, false},
		{"api key global admin certs read", apiKeyAdmin, ActionCertsRead, &org1, true},
		{"multi binding certs write own org", multiBinding, ActionCertsWrite, &org1, false},
		{"multi binding certs write other org", multiBinding, ActionCertsWrite, &org2, true},
		{"org-admin sites write own", orgAdmin, ActionSitesWrite, &org1, true},
		{"org-admin bindings write own", orgAdmin, ActionBindingsWrite, &org1, true},
		{"org-admin bindings write global", orgAdmin, ActionBindingsWrite, nil, false},
		{"org-admin users read shared", orgAdmin, ActionUsersRead, nil, true},
		{"org-admin users write", orgAdmin, ActionUsersWrite, nil, false},
		{"viewer sites read", viewer, ActionSitesRead, &org1, true},
		{"viewer users read", viewer, ActionUsersRead, nil, false},
		{"operator apikeys write", operator, ActionAPIKeysWrite, &org1, false},
		{"read key certs read own org", readKey, ActionCertsRead, &org1, true},
		{"read key certs read other org", readKey, ActionCertsRead, &org2, false},
		{"read key certs write", readKey, ActionCertsWrite, &org1, false},
		{"read key orgs read shared", readKey, ActionOrgsRead, nil, true},
		{"bound key limited by its binding", boundKey, ActionCertsWrite, &org1, false},
		{"bound key read via binding", boundKey, ActionCertsRead, &org1, true},
		{"key without info denied", bareKey, ActionCertsRead, &org1, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Can(tc.p, tc.action, tc.org); got != tc.want {
				t.Fatalf("Can = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestAdminHasAllActions(t *testing.T) {
	for _, a := range AllActions {
		if !Can(principal(RoleAdmin, nil), a, nil) {
			t.Fatalf("admin lacks %s", a)
		}
	}
}

func TestEveryRoleDefined(t *testing.T) {
	for _, r := range []string{RoleAdmin, RoleOrgAdmin, RoleOperator, RoleViewer, RoleAuditor} {
		if _, ok := roleActions[r]; !ok {
			t.Fatalf("role %s has no action set", r)
		}
	}
}

func TestScopeTables(t *testing.T) {
	for _, s := range APIKeyScopes {
		if _, ok := ScopeGrant[s]; !ok {
			t.Fatalf("scope %s has no grant action", s)
		}
		if len(scopeActions[s]) == 0 {
			t.Fatalf("scope %s grants nothing", s)
		}
	}
}

func TestOrgsWith(t *testing.T) {
	org1, org2 := uuid.New(), uuid.New()
	p := authn.Principal{Kind: authn.KindUser, OrgIDs: []uuid.UUID{org1, org2},
		Bindings: []authn.Binding{{Role: RoleAuditor, OrgID: &org1}, {Role: RoleViewer, OrgID: &org2}}}
	if got := OrgsWith(p, ActionAuditRead); len(got) != 1 || got[0] != org1 {
		t.Fatalf("OrgsWith = %v", got)
	}
}
