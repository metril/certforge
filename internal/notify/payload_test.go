package notify_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/notify"
)

func TestPayloadShape(t *testing.T) {
	orgID := uuid.New()
	evID := uuid.New()
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	ev := notify.Event{
		ID:       evID,
		Kind:     "cert.expiring",
		At:       at,
		OrgID:    &orgID,
		Severity: "warning",
		Resource: notify.Resource{Type: "certificate", ID: "cert-1", Name: "example.com"},
		Summary:  "example.com expires soon",
		Details:  map[string]any{"notAfter": "2026-02-01T00:00:00Z", "secretKey": "should-not-appear"},
	}

	b := notify.Payload(ev, notify.Target{OrgName: "Acme", BaseURL: "https://cf.example", Version: "1.2.3"})

	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("Payload did not produce valid JSON: %v", err)
	}

	if doc["id"] != evID.String() {
		t.Errorf("id = %v, want %v", doc["id"], evID.String())
	}
	if doc["kind"] != "cert.expiring" {
		t.Errorf("kind = %v", doc["kind"])
	}
	if doc["severity"] != "warning" {
		t.Errorf("severity = %v", doc["severity"])
	}
	if doc["summary"] != "example.com expires soon" {
		t.Errorf("summary = %v", doc["summary"])
	}

	org, ok := doc["org"].(map[string]any)
	if !ok {
		t.Fatalf("org is not an object: %v", doc["org"])
	}
	if org["id"] != orgID.String() || org["name"] != "Acme" {
		t.Errorf("org = %v", org)
	}

	resource, ok := doc["resource"].(map[string]any)
	if !ok {
		t.Fatalf("resource is not an object: %v", doc["resource"])
	}
	if resource["type"] != "certificate" || resource["id"] != "cert-1" || resource["name"] != "example.com" {
		t.Errorf("resource = %v", resource)
	}

	details, ok := doc["details"].(map[string]any)
	if !ok {
		t.Fatalf("details is not an object: %v", doc["details"])
	}
	if _, present := details["secretKey"]; present {
		t.Error("Payload let an unlisted detail key through")
	}
	if details["notAfter"] != "2026-02-01T00:00:00Z" {
		t.Errorf("notAfter detail = %v, want passed through (allowlisted)", details["notAfter"])
	}
}

func TestPayloadGlobalEventHasNullOrg(t *testing.T) {
	ev := notify.Event{
		ID:       uuid.New(),
		Kind:     "backup.completed",
		At:       time.Now(),
		OrgID:    nil,
		Severity: "info",
		Resource: notify.Resource{Type: "backup", ID: "certforge-20260101T000000Z.cfbak", Name: "certforge-20260101T000000Z.cfbak"},
		Summary:  "Backup completed",
	}

	b := notify.Payload(ev, notify.Target{})

	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	if doc["org"] != nil {
		t.Errorf("org = %v, want null for a global event", doc["org"])
	}
}
