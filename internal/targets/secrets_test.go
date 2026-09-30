package targets_test

import (
	"encoding/json"
	"testing"

	"github.com/metril/certforge/internal/targets"
)

const roundTripSchema = `{
  "type": "object",
  "properties": {
    "url": {"type": "string"},
    "token": {"type": "string", "secret": true},
    "note": {"type": "string", "secret": true}
  }
}`

func TestSplitMergeRoundTrip(t *testing.T) {
	canonical := json.RawMessage(`{"url":"https://example.test","token":"tok","note":""}`)

	pub, secrets, err := targets.Split(json.RawMessage(roundTripSchema), canonical)
	if err != nil {
		t.Fatalf("Split: %v", err)
	}
	var pubDoc map[string]any
	if err := json.Unmarshal(pub, &pubDoc); err != nil {
		t.Fatalf("public is not valid JSON: %v", err)
	}
	if _, ok := pubDoc["token"]; ok {
		t.Errorf("public still has token: %v", pubDoc)
	}
	if _, ok := pubDoc["note"]; ok {
		t.Errorf("public still has note: %v", pubDoc)
	}
	if pubDoc["url"] != "https://example.test" {
		t.Errorf("public.url = %v, want https://example.test", pubDoc["url"])
	}
	if secrets["token"] != "tok" {
		t.Errorf("secrets[token] = %q, want tok", secrets["token"])
	}
	if _, ok := secrets["note"]; ok {
		t.Errorf("Split kept the empty note secret: %v", secrets)
	}

	merged, err := targets.Merge(pub, map[string]string{"token": "tok"})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	pub2, secrets2, err := targets.Split(json.RawMessage(roundTripSchema), merged)
	if err != nil {
		t.Fatalf("Split (round 2): %v", err)
	}
	var pubDoc2 map[string]any
	if err := json.Unmarshal(pub2, &pubDoc2); err != nil {
		t.Fatalf("public (round 2) is not valid JSON: %v", err)
	}
	if pubDoc2["url"] != "https://example.test" {
		t.Errorf("public.url (round 2) = %v, want https://example.test", pubDoc2["url"])
	}
	if secrets2["token"] != "tok" {
		t.Errorf("secrets[token] (round 2) = %q, want tok", secrets2["token"])
	}
}

func TestSecretPropsRules(t *testing.T) {
	cases := []struct {
		name    string
		schema  string
		want    []string
		wantErr bool
	}{
		{"none", `{"properties":{"url":{"type":"string"}}}`, nil, false},
		{"one", `{"properties":{"token":{"type":"string","secret":true}}}`, []string{"token"}, false},
		{"sorted", `{"properties":{"z":{"type":"string","secret":true},"a":{"type":"string","secret":true}}}`, []string{"a", "z"}, false},
		{"non-string type rejected", `{"properties":{"token":{"type":"boolean","secret":true}}}`, nil, true},
		{"pattern rejected", `{"properties":{"token":{"type":"string","secret":true,"pattern":"^x"}}}`, nil, true},
		{"enum rejected", `{"properties":{"token":{"type":"string","secret":true,"enum":["a"]}}}`, nil, true},
		{"const rejected", `{"properties":{"token":{"type":"string","secret":true,"const":"a"}}}`, nil, true},
		{"format rejected", `{"properties":{"token":{"type":"string","secret":true,"format":"uri"}}}`, nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := targets.SecretProps(json.RawMessage(c.schema))
			if c.wantErr {
				if err == nil {
					t.Fatal("SecretProps did not fail")
				}
				return
			}
			if err != nil {
				t.Fatalf("SecretProps: %v", err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("SecretProps = %v, want %v", got, c.want)
			}
			for i := range c.want {
				if got[i] != c.want[i] {
					t.Fatalf("SecretProps = %v, want %v", got, c.want)
				}
			}
		})
	}
}
