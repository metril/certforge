package targets

import (
	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/notify/httpx"
)

// HTTPFactory builds an outbound httpx.Client for a target's own network
// calls, forcing the loopback policy the caller has already decided:
// AllowLoopback true for an agent-side target (inside whatever network the
// agent itself reaches), or the org's allowLoopbackUrls setting for a
// server-side one.
type HTTPFactory struct {
	AllowLoopback bool
}

// New builds an httpx.Client from o, overriding o.AllowLoopback with f's.
func (f HTTPFactory) New(o httpx.Options) (*httpx.Client, error) {
	o.AllowLoopback = f.AllowLoopback
	return httpx.New(o)
}

// WebSocket builds websocket.DialOptions whose HTTP client carries the same
// SSRF-safe dial policy, CA bundle and no-redirect rule as New.
func (f HTTPFactory) WebSocket(o httpx.Options) (*websocket.DialOptions, error) {
	c, err := f.New(o)
	if err != nil {
		return nil, err
	}
	return &websocket.DialOptions{HTTPClient: c.HTTPClient()}, nil
}
