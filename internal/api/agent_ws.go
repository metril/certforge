package api

import (
	"net/http"

	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/agentproto"
)

// ws upgrades an authenticated agent to its socket and hands it to the hub.
func (a *agentAPI) ws(w http.ResponseWriter, r *http.Request) {
	if a.d.Hub == nil {
		Write(w, http.StatusServiceUnavailable, "Service unavailable", "The agent hub is not running.")
		return
	}
	c := agentClient(r.Context())
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return // Accept has written the error response
	}
	conn.SetReadLimit(1 << 20)
	if err := a.d.Hub.Serve(r.Context(), c.ID, agentproto.WS{C: conn}, a.d.Agents); err != nil {
		a.d.Log.Debug("agent socket ended", "client", c.ID, "err", err)
	}
}
