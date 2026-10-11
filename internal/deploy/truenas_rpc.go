package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/coder/websocket"
)

// Server-API facts that differ across TrueNAS releases and are unverified
// against a live box. Keep every one of them here.
const (
	truenasEndpoint              = "/api/current"            // VERIFY: JSON-RPC WebSocket path
	truenasLoginMechanism        = "API_KEY_PLAIN"           // VERIFY: auth.login_ex mechanism
	truenasMethodLoginEx         = "auth.login_ex"           // VERIFY
	truenasMethodLoginKey        = "auth.login_with_api_key" // fallback for older releases
	truenasMethodJobWait         = "core.job_wait"           // VERIFY: falls back to polling core.get_jobs
	truenasMethodRestartUI       = "system.general.ui_restart"
	truenasCreateType            = "CERTIFICATE_CREATE_IMPORTED"
	truenasMethodNotFound        = -32601
	truenasMaxMessage      int64 = 8 << 20
)

// truenasUIRestartParams is the ui_restart argument list. VERIFY.
var truenasUIRestartParams = []any{}

// rpcError is a JSON-RPC error object returned by the server.
type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    struct {
		Errname string `json:"errname"`
		Reason  string `json:"reason"`
	} `json:"data"`
}

func (e *rpcError) Error() string {
	s := fmt.Sprintf("rpc error %d: %s", e.Code, e.Message)
	if e.Data.Reason != "" {
		s += ": " + e.Data.Reason
	}
	return s
}

// rpcClient is a minimal sequential JSON-RPC 2.0 client over a WebSocket.
type rpcClient struct {
	conn *websocket.Conn
	next int
}

func newRPCClient(conn *websocket.Conn) *rpcClient {
	conn.SetReadLimit(truenasMaxMessage)
	return &rpcClient{conn: conn}
}

// send writes a request and returns its id.
func (c *rpcClient) send(ctx context.Context, method string, params any) (int, error) {
	c.next++
	b, err := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": c.next, "method": method, "params": params})
	if err != nil {
		return 0, err
	}
	return c.next, c.conn.Write(ctx, websocket.MessageText, b)
}

// call sends one request and reads until its response, skipping
// notifications and responses to other ids.
func (c *rpcClient) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	id, err := c.send(ctx, method, params)
	if err != nil {
		return nil, err
	}
	for {
		_, b, err := c.conn.Read(ctx)
		if err != nil {
			return nil, err
		}
		var m struct {
			ID     *int            `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *rpcError       `json:"error"`
		}
		if json.Unmarshal(b, &m) != nil || m.ID == nil || *m.ID != id {
			continue
		}
		if m.Error != nil {
			return nil, m.Error
		}
		return m.Result, nil
	}
}

// callAllowClose is call for a request after which the server may drop the
// socket (ui_restart): a close or EOF instead of a reply is success.
func (c *rpcClient) callAllowClose(ctx context.Context, method string, params any) error {
	_, err := c.call(ctx, method, params)
	var re *rpcError
	if err == nil || errors.As(err, &re) {
		return err
	}
	if ctx.Err() != nil {
		return err
	}
	return nil
}

func isMethodNotFound(err error) bool {
	var re *rpcError
	return errors.As(err, &re) && re.Code == truenasMethodNotFound
}

func oneLine(s string, max int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s)
	if len(s) > max {
		s = s[:max]
	}
	return s
}
