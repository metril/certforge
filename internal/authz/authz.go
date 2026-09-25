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
	ActionSitesRead     Action = "sites:read"
	ActionSitesWrite    Action = "sites:write"
	ActionBindingsRead  Action = "bindings:read"
	ActionBindingsWrite Action = "bindings:write"
	ActionAPIKeysRead   Action = "apikeys:read"
	ActionAPIKeysWrite  Action = "apikeys:write"
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
	ActionSitesRead, ActionSitesWrite, ActionBindingsRead, ActionBindingsWrite,
	ActionAPIKeysRead, ActionAPIKeysWrite,
}

var globalOnly = map[Action]bool{
	ActionSettingsWrite: true, ActionOrgsWrite: true, ActionCAsWrite: true, ActionKeysExport: true, ActionUsersWrite: true,
}

var sharedRead = map[Action]bool{ActionOrgsRead: true, ActionSettingsRead: true, ActionCAsRead: true, ActionUsersRead: true}

var viewerActions = []Action{
	ActionOrgsRead, ActionSettingsRead, ActionCAsRead, ActionAccountsRead,
	ActionDNSCredsRead, ActionCertsRead, ActionClientsRead, ActionSitesRead,
}

// APIKeyScopes are the scopes an API key may carry (docs/design.md).
var APIKeyScopes = []string{"certs:read", "certs:write", "certs:issue", "keys:export", "clients:write", "admin"}

// ScopeGrant is the action the creator must hold, in the key's org (or
// globally for an org-less key), to put a scope on a key.
var ScopeGrant = map[string]Action{
	"certs:read": ActionCertsRead, "certs:write": ActionCertsWrite, "certs:issue": ActionCertsIssue,
	"keys:export": ActionKeysExport, "clients:write": ActionClientsWrite, "admin": ActionSettingsWrite,
}

var scopeActions = map[string][]Action{
	"certs:read":    {ActionCertsRead, ActionOrgsRead, ActionSitesRead, ActionCAsRead, ActionAccountsRead, ActionDNSCredsRead},
	"certs:write":   {ActionCertsWrite},
	"certs:issue":   {ActionCertsIssue},
	"keys:export":   {ActionKeysExport},
	"clients:write": {ActionClientsRead, ActionClientsWrite},
	"admin":         AllActions,
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
// (nil for global resources). API keys are limited by their scopes, their
// org and their own bindings, and never exceed their creator's bindings.
func Can(p authn.Principal, action Action, orgID *uuid.UUID) bool {
	switch p.Kind {
	case authn.KindUser:
	case authn.KindAPIKey:
		if !keyAllows(p.APIKey, action, orgID) {
			return false
		}
	default:
		return false
	}
	return bindingsAllow(p.Bindings, action, orgID)
}

func keyAllows(k *authn.APIKeyInfo, action Action, orgID *uuid.UUID) bool {
	if k == nil {
		return false
	}
	scoped := false
	for _, s := range k.Scopes {
		if slices.Contains(scopeActions[s], action) {
			scoped = true
			break
		}
	}
	if !scoped {
		return false
	}
	if k.OrgID != nil {
		if orgID == nil && !sharedRead[action] {
			return false
		}
		if orgID != nil && *orgID != *k.OrgID {
			return false
		}
	}
	return len(k.Bindings) == 0 || bindingsAllow(k.Bindings, action, orgID)
}

func bindingsAllow(bindings []authn.Binding, action Action, orgID *uuid.UUID) bool {
	for _, b := range bindings {
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

// OrgsWith returns the principal's visible orgs in which it may perform action.
func OrgsWith(p authn.Principal, action Action) []uuid.UUID {
	out := []uuid.UUID{}
	for _, id := range p.OrgIDs {
		if Can(p, action, &id) {
			out = append(out, id)
		}
	}
	return out
}
