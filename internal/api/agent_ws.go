package api

import (
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/agents"
)

// ws upgrades a signed request to the agent's socket. The upgrade GET is
// signed by the agent's key like any other agent request (certificate in
// Cf-Agent-Cert, the agent's ephemeral key in Cf-Ephemeral); nothing about the
// TLS layer or a client certificate counts. The first frame is a hello_ack
// signed by the responder over both ephemeral keys and the upgrade nonce; every
// frame after it is sealed under the keys derived from them, so a proxy that
// terminates TLS can neither read nor inject anything.
func (a *agentAPI) ws(w http.ResponseWriter, r *http.Request) {
	if a.d.Hub == nil {
		Write(w, http.StatusServiceUnavailable, "Service unavailable", "The agent hub is not running.")
		return
	}
	now := a.clock()
	rs := a.responder()
	if rs == nil {
		Write(w, http.StatusServiceUnavailable, "Service unavailable", "The agent responder identity is not ready.")
		return
	}
	der, err := base64.StdEncoding.DecodeString(r.Header.Get(agentproto.HeaderAgentCert))
	if err != nil || len(der) == 0 || len(der) > 8<<10 {
		a.reject(w, http.StatusUnauthorized, agentproto.ErrCodeAuth)
		return
	}
	clientID, serial, pub, err := a.d.Agents.VerifyAgentCert(r.Context(), der)
	if err != nil {
		a.rejectErr(w, err, "")
		return
	}
	keyID := clientID.String() + ":" + serial
	p, err := a.verify(r, nil, now, func(id string) (*ecdsa.PublicKey, error) {
		if id != keyID {
			return nil, agentproto.ErrSig
		}
		return pub, nil
	})
	if err != nil {
		a.reject(w, http.StatusUnauthorized, errCode(err))
		return
	}
	if code := a.checkFresh(p, now); code != "" {
		a.refuse(w, http.StatusUnauthorized, code, p.Nonce)
		return
	}
	c, err := a.d.Agents.AuthenticateKey(r.Context(), clientID, serial)
	if err != nil {
		a.rejectErr(w, err, p.Nonce)
		return
	}
	raw, err := base64.StdEncoding.DecodeString(p.Ephemeral)
	peer, perr := ecdh.P256().NewPublicKey(raw)
	if err != nil || perr != nil {
		a.refuse(w, http.StatusBadRequest, "ephemeral", p.Nonce)
		return
	}
	local, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		a.rejectErr(w, err, p.Nonce)
		return
	}
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	sess, err := agentproto.NewSession(local, peer, salt, false)
	if err != nil {
		a.rejectErr(w, err, p.Nonce)
		return
	}
	ack := agentproto.HelloAck{Ephemeral: base64.StdEncoding.EncodeToString(local.PublicKey().Bytes()),
		Session: base64.RawURLEncoding.EncodeToString(salt), Chain: append([]string{rs.leaf}, rs.chain...)}
	if err := agentproto.SignHelloAck(&ack, rs.key, p.Ephemeral, p.Nonce, now); err != nil {
		a.rejectErr(w, err, p.Nonce)
		return
	}
	first, err := agentproto.Marshal(ack)
	if err != nil {
		a.rejectErr(w, err, p.Nonce)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return // Accept has written the error response
	}
	conn.SetReadLimit(agentproto.MaxMessage + agentproto.FrameOverhead)
	if err := (agentproto.WS{C: conn}).WriteMsg(r.Context(), first); err != nil {
		_ = conn.CloseNow()
		return
	}
	// A revoke or re-enrolment that committed between the check above and the
	// hub registering this connection must not leave it open: re-run the same
	// check the hub is now holding a slot for.
	verify := func(ctx context.Context) error {
		_, err := a.d.Agents.AuthenticateKey(ctx, clientID, serial)
		return err
	}
	// The serial travels with the socket's context so OnMessage can re-run
	// AuthenticateKey on every message for as long as the connection lives.
	ctx := agents.WithSerial(r.Context(), serial)
	if err := a.d.Hub.Serve(ctx, c.ID, agentproto.NewSealedWS(conn, sess, ack.Session), a.d.Agents, verify); err != nil {
		a.d.Log.Debug("agent socket ended", "client", c.ID, "err", err)
	}
}
