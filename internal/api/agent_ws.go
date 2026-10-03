package api

import (
	"context"
	"net/http"

	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
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
	conn.SetReadLimit(agentproto.MaxMessage)
	// A revoke or re-enrolment that committed between requireAgent's own
	// check and the hub registering this connection must not leave it
	// open: re-run the same check the hub is now holding a slot for.
	verify := func(ctx context.Context) error {
		_, err := a.d.Agents.Authenticate(ctx, leaf)
		return err
	}
	// The leaf travels with the socket's context so OnMessage can re-run
	// Authenticate (serial included) on every message for as long as the
	// connection lives, not only here at accept time.
	ctx := agents.WithLeaf(r.Context(), leaf)
	if err := a.d.Hub.Serve(ctx, c.ID, agentproto.WS{C: conn}, a.d.Agents, verify); err != nil {
		a.d.Log.Debug("agent socket ended", "client", c.ID, "err", err)
	}
}
