package vault

import (
	"context"
	"net/http"
	"testing"
)

// TestKVPutShape covers the KV v2 write envelope: data nested under
// "data", and "options.cas" present only when cas is non-nil.
func TestKVPutShape(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handle(http.MethodPost, "/v1/secret/data/certs/foo", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"version": 1}})
	})

	c := newTestClient(t, fv.URL(), TokenAuth{Token: "t"})

	v, err := c.KVPut(context.Background(), "secret", "certs/foo", map[string]any{"cert": "PEM"}, nil)
	if err != nil {
		t.Fatalf("KVPut (no cas): %v", err)
	}
	if v != 1 {
		t.Fatalf("version = %d, want 1", v)
	}
	var body map[string]any
	if err := fv.LastBody(http.MethodPost, "/v1/secret/data/certs/foo", &body); err != nil {
		t.Fatalf("LastBody: %v", err)
	}
	if _, ok := body["options"]; ok {
		t.Fatalf("body has options when cas is nil: %+v", body)
	}
	data, ok := body["data"].(map[string]any)
	if !ok || data["cert"] != "PEM" {
		t.Fatalf("body.data = %+v, want {cert: PEM}", body["data"])
	}

	cas := 3
	if _, err := c.KVPut(context.Background(), "secret", "certs/foo", map[string]any{"cert": "PEM2"}, &cas); err != nil {
		t.Fatalf("KVPut (cas): %v", err)
	}
	if err := fv.LastBody(http.MethodPost, "/v1/secret/data/certs/foo", &body); err != nil {
		t.Fatalf("LastBody: %v", err)
	}
	opts, ok := body["options"].(map[string]any)
	if !ok {
		t.Fatalf("body has no options when cas is set: %+v", body)
	}
	if casVal, ok := opts["cas"].(float64); !ok || int(casVal) != 3 {
		t.Fatalf("options.cas = %v, want 3", opts["cas"])
	}
}
