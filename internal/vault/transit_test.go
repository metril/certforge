package vault

import (
	"context"
	"net/http"
	"testing"
)

// TestTransitRoundTrip covers encrypt, decrypt and rewrap: the request
// envelope (base64 plaintext in, ciphertext string passed through as-is)
// and the response parsing.
func TestTransitRoundTrip(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()

	fv.handle(http.MethodPost, "/v1/transit/encrypt/kek", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Plaintext string `json:"plaintext"`
		}
		if err := fv.LastBody(http.MethodPost, "/v1/transit/encrypt/kek", &body); err != nil {
			t.Fatalf("decode encrypt body: %v", err)
		}
		if body.Plaintext != "aGVsbG8=" { // base64("hello")
			t.Fatalf("plaintext = %q, want base64 of \"hello\"", body.Plaintext)
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"ciphertext": "vault:v1:abc"}})
	})
	fv.handle(http.MethodPost, "/v1/transit/decrypt/kek", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Ciphertext string `json:"ciphertext"`
		}
		if err := fv.LastBody(http.MethodPost, "/v1/transit/decrypt/kek", &body); err != nil {
			t.Fatalf("decode decrypt body: %v", err)
		}
		if body.Ciphertext != "vault:v1:abc" {
			t.Fatalf("ciphertext = %q, want vault:v1:abc", body.Ciphertext)
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"plaintext": "aGVsbG8="}})
	})
	fv.handle(http.MethodPost, "/v1/transit/rewrap/kek", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Ciphertext string `json:"ciphertext"`
		}
		if err := fv.LastBody(http.MethodPost, "/v1/transit/rewrap/kek", &body); err != nil {
			t.Fatalf("decode rewrap body: %v", err)
		}
		if body.Ciphertext != "vault:v1:abc" {
			t.Fatalf("ciphertext = %q, want vault:v1:abc", body.Ciphertext)
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"ciphertext": "vault:v2:def"}})
	})

	c := newTestClient(t, fv.URL(), TokenAuth{Token: "t"})
	ctx := context.Background()

	ct, err := c.TransitEncrypt(ctx, "transit", "kek", []byte("hello"))
	if err != nil {
		t.Fatalf("TransitEncrypt: %v", err)
	}
	if string(ct) != "vault:v1:abc" {
		t.Fatalf("ciphertext = %q, want vault:v1:abc", ct)
	}

	pt, err := c.TransitDecrypt(ctx, "transit", "kek", ct)
	if err != nil {
		t.Fatalf("TransitDecrypt: %v", err)
	}
	if string(pt) != "hello" {
		t.Fatalf("plaintext = %q, want hello", pt)
	}

	rw, err := c.TransitRewrap(ctx, "transit", "kek", ct)
	if err != nil {
		t.Fatalf("TransitRewrap: %v", err)
	}
	if string(rw) != "vault:v2:def" {
		t.Fatalf("rewrapped = %q, want vault:v2:def", rw)
	}
}

// TestTransitKeyInfo covers the GET .../keys/<key> version fields.
func TestTransitKeyInfo(t *testing.T) {
	fv := newFakeVault()
	defer fv.Close()
	fv.handle(http.MethodGet, "/v1/transit/keys/kek", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"data": map[string]any{"latest_version": 3, "min_decryption_version": 2}})
	})

	c := newTestClient(t, fv.URL(), TokenAuth{Token: "t"})
	info, err := c.TransitKeyInfo(context.Background(), "transit", "kek")
	if err != nil {
		t.Fatalf("TransitKeyInfo: %v", err)
	}
	if info.LatestVersion != 3 || info.MinDecryptionVersion != 2 {
		t.Fatalf("info = %+v, want {3 2}", info)
	}
	if fv.CallCount(http.MethodGet, "/v1/transit/keys/kek") != 1 {
		t.Fatal("expected exactly one call")
	}
}
