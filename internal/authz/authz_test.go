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
