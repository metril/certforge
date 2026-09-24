// Package authz decides what a principal may do. Roles map to action sets.
// Bindings scope a role globally or to one org.
package authz

import (
	"slices"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/authn"
)

// Action is a permission checked by Can.
type Action string

// Actions.
const (
	ActionOrgsRead      Action = "orgs:read"
	ActionOrgsWrite     Action = "orgs:write"
	ActionSettingsRead  Action = "settings:read"
	ActionSettingsWrite Action = "settings:write"
	ActionUsersRead     Action = "users:read"
	ActionUsersWrite    Action = "users:write"
	ActionCAsRead       Action = "cas:read"
	ActionCAsWrite      Action = "cas:write"
	ActionAccountsRead  Action = "accounts:read"
	ActionAccountsWrite Action = "accounts:write"
	ActionDNSCredsRead  Action = "dnscreds:read"
	ActionDNSCredsWrite Action = "dnscreds:write"
	ActionCertsRead     Action = "certs:read"
	ActionCertsWrite    Action = "certs:write"
	ActionCertsIssue    Action = "certs:issue"
	ActionKeysExport    Action = "keys:export"
	ActionClientsRead   Action = "clients:read"
	ActionClientsWrite  Action = "clients:write"
	ActionAuditRead     Action = "audit:read"
)

// Roles, matching the role_bindings.role check constraint.
const (
	RoleAdmin    = "admin"
	RoleOrgAdmin = "org-admin"
	RoleOperator = "operator"
	RoleViewer   = "viewer"
	RoleAuditor  = "auditor"
)

// AllActions lists every action.
var AllActions = []Action{
	ActionOrgsRead, ActionOrgsWrite, ActionSettingsRead, ActionSettingsWrite,
	ActionUsersRead, ActionUsersWrite, ActionCAsRead, ActionCAsWrite,
	ActionAccountsRead, ActionAccountsWrite, ActionDNSCredsRead, ActionDNSCredsWrite,
	ActionCertsRead, ActionCertsWrite, ActionCertsIssue, ActionKeysExport,
	ActionClientsRead, ActionClientsWrite, ActionAuditRead,
}

var globalOnly = map[Action]bool{
	ActionSettingsWrite: true, ActionOrgsWrite: true, ActionCAsWrite: true, ActionKeysExport: true,
}

var sharedRead = map[Action]bool{ActionOrgsRead: true, ActionSettingsRead: true, ActionCAsRead: true}

var viewerActions = []Action{
	ActionOrgsRead, ActionSettingsRead, ActionCAsRead, ActionAccountsRead,
	ActionDNSCredsRead, ActionCertsRead, ActionClientsRead,
}

var roleActions = map[string]map[Action]bool{
	RoleAdmin:    set(AllActions),
	RoleOrgAdmin: set(slices.DeleteFunc(slices.Clone(AllActions), func(a Action) bool { return globalOnly[a] })),
	RoleOperator: set(slices.Concat(viewerActions, []Action{
		ActionAccountsWrite, ActionDNSCredsWrite, ActionCertsWrite, ActionCertsIssue, ActionClientsWrite,
	})),
	RoleViewer:  set(viewerActions),
	RoleAuditor: set(slices.Concat(viewerActions, []Action{ActionAuditRead})),
}

func set(actions []Action) map[Action]bool {
	m := make(map[Action]bool, len(actions))
	for _, a := range actions {
		m[a] = true
	}
	return m
}

// Can reports whether p may perform action on a resource in orgID
// (nil for global resources).
func Can(p authn.Principal, action Action, orgID *uuid.UUID) bool {
	if p.Kind != authn.KindUser && p.Kind != authn.KindAPIKey {
		return false
	}
	for _, b := range p.Bindings {
		if !roleActions[b.Role][action] {
			continue
		}
		if b.OrgID == nil {
			return true
		}
		if globalOnly[action] {
			continue
		}
		if orgID == nil {
			if sharedRead[action] {
				return true
			}
			continue
		}
		if *b.OrgID == *orgID {
			return true
		}
	}
	return false
}
