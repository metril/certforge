package vault

import (
	"context"
	"fmt"
	"net/http"
)

// KVPut writes data to a KV v2 secrets engine at mount/path and returns the
// new version. cas, when non-nil, sets the check-and-set version Vault must
// currently be at; nil omits the option entirely, an unconditional write.
func (c *Client) KVPut(ctx context.Context, mount, path string, data map[string]any, cas *int) (int, error) {
	body := map[string]any{"data": data}
	if cas != nil {
		body["options"] = map[string]any{"cas": *cas}
	}
	reqPath := fmt.Sprintf("/v1/%s/data/%s", mount, path)
	var resp struct {
		Data struct {
			Version int `json:"version"`
		} `json:"data"`
	}
	if err := c.Redact(c.doJSON(ctx, http.MethodPost, reqPath, body, &resp, requestOpts{})); err != nil {
		return 0, err
	}
	return resp.Data.Version, nil
}
