package api

import (
	"context"
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
	leaf := r.TLS.PeerCertificates[0]
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return // Accept has written the error response
	}
	conn.SetReadLimit(1 << 20)
	// A revoke or re-enrolment that committed between requireAgent's own
	// check and the hub registering this connection must not leave it
	// open: re-run the same check the hub is now holding a slot for.
	verify := func(ctx context.Context) error {
		_, err := a.d.Agents.Authenticate(ctx, leaf)
		return err
	}
	if err := a.d.Hub.Serve(r.Context(), c.ID, agentproto.WS{C: conn}, a.d.Agents, verify); err != nil {
		a.d.Log.Debug("agent socket ended", "client", c.ID, "err", err)
	}
}
