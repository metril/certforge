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
	// ActionDNSCredsReveal returns a stored DNS credential secret in plaintext
	// (global admin only, like ActionKeysExport).
	ActionDNSCredsReveal Action = "dnscreds:reveal"
	ActionCertsRead      Action = "certs:read"
	ActionCertsWrite     Action = "certs:write"
	ActionCertsIssue     Action = "certs:issue"
	ActionKeysExport     Action = "keys:export"
	ActionClientsRead    Action = "clients:read"
	ActionClientsWrite   Action = "clients:write"
	ActionAuditRead      Action = "audit:read"
	ActionSitesRead      Action = "sites:read"
	ActionSitesWrite     Action = "sites:write"
	ActionBindingsRead   Action = "bindings:read"
	ActionBindingsWrite  Action = "bindings:write"
	ActionAPIKeysRead    Action = "apikeys:read"
	ActionAPIKeysWrite   Action = "apikeys:write"
	ActionDeliveryRead   Action = "delivery:read"
	ActionDeliveryWrite  Action = "delivery:write"
	ActionAlertsRead     Action = "alerts:read"
	ActionAlertsWrite    Action = "alerts:write"
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
	ActionAccountsRead, ActionAccountsWrite, ActionDNSCredsRead, ActionDNSCredsWrite, ActionDNSCredsReveal,
	ActionCertsRead, ActionCertsWrite, ActionCertsIssue, ActionKeysExport,
	ActionClientsRead, ActionClientsWrite, ActionAuditRead,
	ActionSitesRead, ActionSitesWrite, ActionBindingsRead, ActionBindingsWrite,
	ActionAPIKeysRead, ActionAPIKeysWrite,
	ActionDeliveryRead, ActionDeliveryWrite,
	ActionAlertsRead, ActionAlertsWrite,
}

var globalOnly = map[Action]bool{
	ActionSettingsWrite: true, ActionOrgsWrite: true, ActionCAsWrite: true, ActionKeysExport: true, ActionUsersWrite: true,
	ActionDNSCredsReveal: true,
}

var sharedRead = map[Action]bool{ActionOrgsRead: true, ActionSettingsRead: true, ActionCAsRead: true, ActionUsersRead: true}

var viewerActions = []Action{
	ActionOrgsRead, ActionSettingsRead, ActionCAsRead, ActionAccountsRead,
	ActionDNSCredsRead, ActionCertsRead, ActionClientsRead, ActionSitesRead,
	ActionDeliveryRead, ActionAlertsRead,
}

// APIKeyScopes are the scopes an API key may carry (docs/internals/history/design.md, plus
// Phase 3's clients:read and delivery scopes, and Phase 6A's alerts scopes).
var APIKeyScopes = []string{"certs:read", "certs:write", "certs:issue", "keys:export", "dnscreds:reveal",
	"clients:read", "clients:write", "delivery:read", "delivery:write",
	"alerts:read", "alerts:write", "admin"}

// ScopeGrant is the action the creator must hold, in the key's org (or
// globally for an org-less key), to put a scope on a key.
var ScopeGrant = map[string]Action{
	"certs:read": ActionCertsRead, "certs:write": ActionCertsWrite, "certs:issue": ActionCertsIssue,
	"keys:export": ActionKeysExport, "dnscreds:reveal": ActionDNSCredsReveal, "clients:read": ActionClientsRead, "clients:write": ActionClientsWrite,
	"delivery:read": ActionDeliveryRead, "delivery:write": ActionDeliveryWrite,
	"alerts:read": ActionAlertsRead, "alerts:write": ActionAlertsWrite, "admin": ActionSettingsWrite,
}

var scopeActions = map[string][]Action{
	"certs:read":      {ActionCertsRead, ActionOrgsRead, ActionSitesRead, ActionCAsRead, ActionAccountsRead, ActionDNSCredsRead},
	"certs:write":     {ActionCertsWrite},
	"certs:issue":     {ActionCertsIssue},
	"keys:export":     {ActionKeysExport},
	"dnscreds:reveal": {ActionDNSCredsRead, ActionDNSCredsReveal},
	"clients:read":    {ActionClientsRead, ActionOrgsRead, ActionSitesRead},
	"clients:write":   {ActionClientsRead, ActionClientsWrite},
	"delivery:read":   {ActionDeliveryRead},
	"delivery:write":  {ActionDeliveryRead, ActionDeliveryWrite},
	"alerts:read":     {ActionAlertsRead},
	"alerts:write":    {ActionAlertsRead, ActionAlertsWrite},
	"admin":           AllActions,
}

var roleActions = map[string]map[Action]bool{
	RoleAdmin:    set(AllActions),
	RoleOrgAdmin: set(slices.DeleteFunc(slices.Clone(AllActions), func(a Action) bool { return globalOnly[a] })),
	RoleOperator: set(slices.Concat(viewerActions, []Action{
		ActionAccountsWrite, ActionDNSCredsWrite, ActionCertsWrite, ActionCertsIssue, ActionClientsWrite,
		ActionDeliveryWrite, ActionAlertsWrite,
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
	case authn.KindAgent:
		return false // agents use only /agent/v1/* on the agent listener
	default:
		return false
	}
	return bindingsAllow(p.Bindings, action, orgID)
}

// CanGlobal reports whether p holds action through a global (org-less)
// binding. Unlike Can(p, action, nil), which also admits org-bound roles for
// the shared-read actions, an org-scoped API key or an org-only binding never
// passes. Use it to decide how much detail a shared-read listing may show.
func CanGlobal(p authn.Principal, action Action) bool {
	switch p.Kind {
	case authn.KindUser:
	case authn.KindAPIKey:
		k := p.APIKey
		if k == nil || k.OrgID != nil || !scopeCovers(k, action) {
			return false
		}
		if len(k.Bindings) > 0 && !globalBindingAllows(k.Bindings, action) {
			return false
		}
	default:
		return false
	}
	return globalBindingAllows(p.Bindings, action)
}

func globalBindingAllows(bindings []authn.Binding, action Action) bool {
	for _, b := range bindings {
		if b.OrgID == nil && roleActions[b.Role][action] {
			return true
		}
	}
	return false
}

func scopeCovers(k *authn.APIKeyInfo, action Action) bool {
	for _, s := range k.Scopes {
		if slices.Contains(scopeActions[s], action) {
			return true
		}
	}
	return false
}

func keyAllows(k *authn.APIKeyInfo, action Action, orgID *uuid.UUID) bool {
	if k == nil {
		return false
	}
	if !scopeCovers(k, action) {
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
