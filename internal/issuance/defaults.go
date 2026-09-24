// Package issuance obtains and renews certificates: effective configuration,
// renewal policy and backoff, the data layer, the river IssueWorker and
// scheduler, and the service used by the API.
package issuance

import (
	"github.com/google/uuid"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/signer"
)

// SettingsKey is the global settings section holding Defaults.
const SettingsKey = "issuance_defaults"

// RenewMode selects how next_renew_at is derived from a certificate lifetime.
type RenewMode string

const (
	RenewDays    RenewMode = "days"    // renew Value days before notAfter
	RenewPercent RenewMode = "percent" // renew when Value% of the lifetime remains
)

// RenewPolicy is the renewal policy. UseARI is stored but unused until Phase 4.
type RenewPolicy struct {
	Mode   RenewMode `json:"mode"`
	Value  int       `json:"value"`
	UseARI bool      `json:"useAri"`
}

// Defaults is one level of issuance settings (global, org, or certificate
// overrides). A nil field inherits from the level above.
type Defaults struct {
	CAID               *uuid.UUID            `json:"caId,omitempty"`
	AccountID          *uuid.UUID            `json:"accountId,omitempty"`
	KeyType            *signer.KeyType       `json:"keyType,omitempty"`
	RenewPolicy        *RenewPolicy          `json:"renewPolicy,omitempty"`
	PreferredChain     *string               `json:"preferredChain,omitempty"`
	ReuseKey           *bool                 `json:"reuseKey,omitempty"`
	MustStaple         *bool                 `json:"mustStaple,omitempty"`
	VerificationRules  *[]challenge.RuleSpec `json:"verificationRules,omitempty"`
	PropagationSeconds *int                  `json:"propagationSeconds,omitempty"`
	Resolvers          *[]string             `json:"resolvers,omitempty"`
}

// Source names the level an effective value came from.
type Source string

const (
	SourceDefault Source = "default" // built-in value; nothing configured
	SourceGlobal  Source = "global"
	SourceOrg     Source = "org"
	SourceCert    Source = "cert"
)

// Field is an effective value and where it came from.
type Field[T any] struct {
	Value  T      `json:"value"`
	Source Source `json:"source"`
}

// Effective is the fully resolved configuration.
type Effective struct {
	CAID               Field[*uuid.UUID]           `json:"caId"`
	AccountID          Field[*uuid.UUID]           `json:"accountId"`
	KeyType            Field[signer.KeyType]       `json:"keyType"`
	RenewPolicy        Field[RenewPolicy]          `json:"renewPolicy"`
	PreferredChain     Field[string]               `json:"preferredChain"`
	ReuseKey           Field[bool]                 `json:"reuseKey"`
	MustStaple         Field[bool]                 `json:"mustStaple"`
	VerificationRules  Field[[]challenge.RuleSpec] `json:"verificationRules"`
	PropagationSeconds Field[int]                  `json:"propagationSeconds"`
	Resolvers          Field[[]string]             `json:"resolvers"`
}

// BuiltinDefaults are the global values used when nothing is configured.
// Percent renewal suits 90-, 45- and 6-day certificates alike.
func BuiltinDefaults() Defaults {
	kt := signer.EC256
	pol := RenewPolicy{Mode: RenewPercent, Value: 33}
	chain, f := "", false
	prop := 120
	rules := []challenge.RuleSpec{}
	res := []string{}
	return Defaults{KeyType: &kt, RenewPolicy: &pol, PreferredChain: &chain, ReuseKey: &f, MustStaple: &f,
		VerificationRules: &rules, PropagationSeconds: &prop, Resolvers: &res}
}

func pick[T any](global, org, cert *T, builtin T) Field[T] {
	switch {
	case cert != nil:
		return Field[T]{*cert, SourceCert}
	case org != nil:
		return Field[T]{*org, SourceOrg}
	case global != nil:
		return Field[T]{*global, SourceGlobal}
	}
	return Field[T]{builtin, SourceDefault}
}

func pickID(global, org, cert *uuid.UUID) Field[*uuid.UUID] {
	switch {
	case cert != nil:
		return Field[*uuid.UUID]{cert, SourceCert}
	case org != nil:
		return Field[*uuid.UUID]{org, SourceOrg}
	case global != nil:
		return Field[*uuid.UUID]{global, SourceGlobal}
	}
	return Field[*uuid.UUID]{nil, SourceDefault}
}

// Resolve merges the three levels field by field: cert beats org beats
// global beats BuiltinDefaults (source "default"). Pass a zero Defaults for
// a missing level.
func Resolve(global, org, cert Defaults) Effective {
	b := BuiltinDefaults()
	return Effective{
		CAID:               pickID(global.CAID, org.CAID, cert.CAID),
		AccountID:          pickID(global.AccountID, org.AccountID, cert.AccountID),
		KeyType:            pick(global.KeyType, org.KeyType, cert.KeyType, *b.KeyType),
		RenewPolicy:        pick(global.RenewPolicy, org.RenewPolicy, cert.RenewPolicy, *b.RenewPolicy),
		PreferredChain:     pick(global.PreferredChain, org.PreferredChain, cert.PreferredChain, *b.PreferredChain),
		ReuseKey:           pick(global.ReuseKey, org.ReuseKey, cert.ReuseKey, *b.ReuseKey),
		MustStaple:         pick(global.MustStaple, org.MustStaple, cert.MustStaple, *b.MustStaple),
		VerificationRules:  pick(global.VerificationRules, org.VerificationRules, cert.VerificationRules, *b.VerificationRules),
		PropagationSeconds: pick(global.PropagationSeconds, org.PropagationSeconds, cert.PropagationSeconds, *b.PropagationSeconds),
		Resolvers:          pick(global.Resolvers, org.Resolvers, cert.Resolvers, *b.Resolvers),
	}
}
