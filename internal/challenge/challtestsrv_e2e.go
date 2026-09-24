//go:build e2e

package challenge

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	legochallenge "github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
)

// challtestsrv is a DNS provider for e2e tests: it sets TXT records on
// Pebble's pebble-challtestsrv through its management API. It exists only in
// binaries built with -tags e2e and is picked like any provider: code
// "e2e-challtestsrv", optional field CHALLTESTSRV_URL (default
// http://challtestsrv:8055, the compose service).
type challtestsrv struct {
	base string
	hc   *http.Client
}

func init() {
	schema := []byte(`{"type":"object","additionalProperties":false,"properties":{"CHALLTESTSRV_URL":{"type":"string","title":"Management URL","description":"pebble-challtestsrv management API. Default http://challtestsrv:8055.","secret":false,"x-group":"credentials"}}}`)
	if err := Register(ProviderMeta{Code: "e2e-challtestsrv", Name: "Pebble challtestsrv (e2e)", Schema: schema},
		func(cfg map[string]string) (legochallenge.Provider, error) {
			base := cfg["CHALLTESTSRV_URL"]
			if base == "" {
				base = "http://challtestsrv:8055"
			}
			return &challtestsrv{base: base, hc: &http.Client{Timeout: 5 * time.Second}}, nil
		}); err != nil {
		panic(err)
	}
}

func (c *challtestsrv) post(ctx context.Context, path string, body map[string]string) error {
	b, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("challtestsrv %s: HTTP %d", path, resp.StatusCode)
	}
	return nil
}

func (c *challtestsrv) Present(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return c.post(context.Background(), "/set-txt", map[string]string{"host": info.FQDN, "value": info.Value})
}

func (c *challtestsrv) CleanUp(domain, _, keyAuth string) error {
	info := dns01.GetChallengeInfo(domain, keyAuth)
	return c.post(context.Background(), "/clear-txt", map[string]string{"host": info.FQDN})
}
