package vault

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
)

// KeyInfo is a Transit key's version state.
type KeyInfo struct {
	LatestVersion        int
	MinDecryptionVersion int
}

type transitCiphertextResponse struct {
	Data struct {
		Ciphertext string `json:"ciphertext"`
	} `json:"data"`
}

// TransitEncrypt wraps plaintext under mount/key, returning Vault's opaque
// ciphertext string (e.g. "vault:v1:...").
func (c *Client) TransitEncrypt(ctx context.Context, mount, key string, plaintext []byte) ([]byte, error) {
	body := map[string]string{"plaintext": base64.StdEncoding.EncodeToString(plaintext)}
	var resp transitCiphertextResponse
	path := fmt.Sprintf("/v1/%s/encrypt/%s", escapePath(mount), escapeSegment(key))
	if err := c.doJSON(ctx, http.MethodPost, path, body, &resp, requestOpts{}); err != nil {
		return nil, c.Redact(err)
	}
	return []byte(resp.Data.Ciphertext), nil
}

// TransitDecrypt unwraps a ciphertext produced by TransitEncrypt or
// TransitRewrap.
func (c *Client) TransitDecrypt(ctx context.Context, mount, key string, ciphertext []byte) ([]byte, error) {
	body := map[string]string{"ciphertext": string(ciphertext)}
	var resp struct {
		Data struct {
			Plaintext string `json:"plaintext"`
		} `json:"data"`
	}
	path := fmt.Sprintf("/v1/%s/decrypt/%s", escapePath(mount), escapeSegment(key))
	if err := c.doJSON(ctx, http.MethodPost, path, body, &resp, requestOpts{}); err != nil {
		return nil, c.Redact(err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(resp.Data.Plaintext)
	if err != nil {
		return nil, c.Redact(fmt.Errorf("vault: decode plaintext: %w", err))
	}
	return plaintext, nil
}

// TransitRewrap re-encrypts ciphertext under key's latest version without
// ever exposing the plaintext to the caller.
func (c *Client) TransitRewrap(ctx context.Context, mount, key string, ciphertext []byte) ([]byte, error) {
	body := map[string]string{"ciphertext": string(ciphertext)}
	var resp transitCiphertextResponse
	path := fmt.Sprintf("/v1/%s/rewrap/%s", escapePath(mount), escapeSegment(key))
	if err := c.doJSON(ctx, http.MethodPost, path, body, &resp, requestOpts{}); err != nil {
		return nil, c.Redact(err)
	}
	return []byte(resp.Data.Ciphertext), nil
}

// TransitKeyInfo reports mount/key's current key-version state.
func (c *Client) TransitKeyInfo(ctx context.Context, mount, key string) (KeyInfo, error) {
	var resp struct {
		Data struct {
			LatestVersion        int `json:"latest_version"`
			MinDecryptionVersion int `json:"min_decryption_version"`
		} `json:"data"`
	}
	path := fmt.Sprintf("/v1/%s/keys/%s", escapePath(mount), escapeSegment(key))
	if err := c.doJSON(ctx, http.MethodGet, path, nil, &resp, requestOpts{}); err != nil {
		return KeyInfo{}, c.Redact(err)
	}
	return KeyInfo{LatestVersion: resp.Data.LatestVersion, MinDecryptionVersion: resp.Data.MinDecryptionVersion}, nil
}
