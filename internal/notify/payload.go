package notify

import (
	"encoding/json"
	"time"
)

// detailAllowlist bounds Payload's details object per kind: only these
// keys ever survive into a delivered payload, so a caller that builds an
// Event.Details map a little too generously (an internal id, a field that
// happens to carry key material) can never leak it to a channel — Payload
// drops anything not listed here instead of passing Details through
// verbatim (contract: "details pass through an allowlist per kind, no key
// material"). cert.issued through agent.cert_expiring are the fields
// Sources (Task 7) actually emits; cert.renewal_failed carries no raw
// cause.Error() (issuance.FailureInfo/ClassifyFailure's classified view
// only — TestFailurePayloadHasNoURLOrHost). monitor.*/backup.* remain
// provisional until Tasks 9/12 emit them for real.
var detailAllowlist = map[string][]string{
	"cert.issued":         {"serial", "notAfter", "names", "caName"},
	"cert.renewal_failed": {"failures", "step", "problemType", "status", "class", "nextAttemptAt"},
	"cert.expiring":       {"commonName", "notAfter"},
	"cert.expired":        {"commonName", "notAfter"},
	"deploy.failed":       {"target", "lastError"},
	"deploy.drift":        {"target"},
	"client.offline":      {"lastSeen"},
	"agent.cert_expiring": {"notAfter"},
	"monitor.mismatch":    {"fingerprint", "expectedFingerprint", "issuer"},
	"monitor.unreachable": {"lastError"},
	"monitor.expiring":    {"notAfter"},
	"monitor.recovered":   {},
	"backup.completed":    {"sizeBytes", "file"},
	"backup.failed":       {"error"},
	"test":                {},
}

// payloadOrg is the wire org{id,name} object; nil renders as JSON null for
// a global event (Wire formats row).
type payloadOrg struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type payloadResource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

// payloadBody is the exact shape Wire formats' webhook/homeassistant body
// row describes: {id, kind, at, severity, org, resource, summary, details}.
type payloadBody struct {
	ID       string          `json:"id"`
	Kind     string          `json:"kind"`
	At       time.Time       `json:"at"`
	Severity string          `json:"severity"`
	Org      *payloadOrg     `json:"org"`
	Resource payloadResource `json:"resource"`
	Summary  string          `json:"summary"`
	Details  map[string]any  `json:"details"`
}

// Payload renders ev as the JSON body every HTTP notifier sends (webhook
// and Home Assistant verbatim; Discord and ntfy build their own shapes
// from the same Event in Task 4, but still filter Details through
// filterDetails). target.OrgName fills org.name; org is null for a global
// event (ev.OrgID == nil).
func Payload(ev Event, target Target) []byte {
	var org *payloadOrg
	if ev.OrgID != nil {
		org = &payloadOrg{ID: ev.OrgID.String(), Name: target.OrgName}
	}
	b, _ := json.Marshal(payloadBody{
		ID:       ev.ID.String(),
		Kind:     ev.Kind,
		At:       ev.At,
		Severity: ev.Severity,
		Org:      org,
		Resource: payloadResource{Type: ev.Resource.Type, ID: ev.Resource.ID, Name: ev.Resource.Name},
		Summary:  ev.Summary,
		Details:  filterDetails(ev.Kind, ev.Details),
	})
	return b
}

// filterDetails returns the subset of details whose keys are allowlisted
// for kind, always non-nil (renders as {} rather than null).
func filterDetails(kind string, details map[string]any) map[string]any {
	out := map[string]any{}
	for _, k := range detailAllowlist[kind] {
		if v, ok := details[k]; ok {
			out[k] = v
		}
	}
	return out
}
