package vault

import (
	"context"
	"fmt"
	"net/http"
)

// KVPut writes data to a KV v2 secrets engine at mount/path. cas, when
// non-nil, sets the check-and-set version Vault must currently be at; nil
// omits the option entirely, an unconditional write.
func (c *Client) KVPut(ctx context.Context, mount, path string, data map[string]any, cas *int) error {
	body := map[string]any{"data": data}
	if cas != nil {
		body["options"] = map[string]any{"cas": *cas}
	}
	reqPath := fmt.Sprintf("/v1/%s/data/%s", mount, path)
	return c.Redact(c.doJSON(ctx, http.MethodPost, reqPath, body, nil, requestOpts{}))
}
