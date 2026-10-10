package api

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/audit"
)

// helloTTL is how long a server ephemeral key from enroll/hello stays usable;
// maxHellos bounds the table an unauthenticated caller can fill.
const (
	helloTTL  = 2 * time.Minute
	maxHellos = 4096
)

type enrollHellos struct {
	mu sync.Mutex
	m  map[string]helloEntry
}

type helloEntry struct {
	priv *ecdh.PrivateKey
	exp  time.Time
}

func (h *enrollHellos) put(id string, priv *ecdh.PrivateKey, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.m == nil {
		h.m = map[string]helloEntry{}
	}
	if len(h.m) >= maxHellos {
		for k, e := range h.m {
			if !now.Before(e.exp) {
				delete(h.m, k)
			}
		}
		if len(h.m) >= maxHellos {
			return false
		}
	}
	h.m[id] = helloEntry{priv: priv, exp: now.Add(helloTTL)}
	return true
}

// take removes and returns the key for id: each ephemeral key serves one
// enrolment attempt, so a replayed body has nothing to open it.
func (h *enrollHellos) take(id string, now time.Time) (*ecdh.PrivateKey, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	e, ok := h.m[id]
	delete(h.m, id)
	if !ok || !now.Before(e.exp) {
		return nil, false
	}
	return e.priv, true
}

var nonceParam = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)

// enrollHello is GET /agent/v1/enroll/hello?nonce=N: a fresh server ephemeral
// key, signed by the responder (with the CA above it, which the agent checks
// against the fingerprint in its token) and bound to N. It needs no
// credential and reveals nothing the CA certificate does not.
func (a *agentAPI) enrollHello(w http.ResponseWriter, r *http.Request) {
	now := a.clock()
	nonce := r.URL.Query().Get("nonce")
	if !nonceParam.MatchString(nonce) {
		a.reject(w, http.StatusBadRequest, "nonce")
		return
	}
	sg := a.responder()
	if sg == nil {
		Write(w, http.StatusServiceUnavailable, "Service unavailable", "The agent responder identity is not ready.")
		return
	}
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		a.rejectErr(w, err, "")
		return
	}
	raw := make([]byte, 16)
	_, _ = rand.Read(raw)
	id := base64.RawURLEncoding.EncodeToString(raw)
	if !a.hellos.put(id, priv, now) {
		w.Header().Set("Retry-After", "30")
		a.reject(w, http.StatusServiceUnavailable, "busy")
		return
	}
	out, _ := json.Marshal(agentproto.EnrollHello{ID: id, Ephemeral: base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
		Chain: sg.chain, ExpiresIn: int(helloTTL.Seconds())})
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "no-store")
	if !a.signResponse(h, http.StatusOK, out, nonce) {
		Write(w, http.StatusServiceUnavailable, "Service unavailable", "The agent responder identity is not ready.")
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
}

// sealedReply answers a verified enrolment request: v (or, for an error, a
// problem) is HPKE-sealed to the agent's key and the response is signed over
// the sealed bytes, bound to the request nonce.
func (a *agentAPI) sealedReply(w http.ResponseWriter, status int, path, nonce string, to *ecdh.PublicKey, v any) {
	pt, _ := json.Marshal(v)
	ct, err := agentproto.HPKESeal(to, agentproto.SealInfo(agentproto.DirS2C, path, nonce), pt)
	if err != nil {
		a.refuse(w, http.StatusInternalServerError, "seal", nonce)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Cache-Control", "no-store")
	if !a.signResponse(h, status, ct, nonce) {
		Write(w, http.StatusServiceUnavailable, "Service unavailable", "The agent responder identity is not ready.")
		return
	}
	w.WriteHeader(status)
	_, _ = w.Write(ct)
}

// sealedErr is sealedReply for a service error.
func (a *agentAPI) sealedErr(w http.ResponseWriter, err error, path, nonce string, to *ecdh.PublicKey) {
	var he *HTTPError
	if errors.As(mapAgentErr(err), &he) {
		a.sealedReply(w, he.Status, path, nonce, to, map[string]any{"title": he.Title, "status": he.Status, "detail": he.Detail})
		return
	}
	a.d.Log.Error("agent enrolment failed", "err", err)
	a.sealedReply(w, http.StatusInternalServerError, path, nonce, to, map[string]any{"title": "Internal server error", "status": http.StatusInternalServerError})
}

func parseP256(b64 string) (*ecdh.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, err
	}
	return ecdh.P256().NewPublicKey(raw)
}

// enroll is POST /agent/v1/enroll: the sealed token proof (see
// agentproto.PathEnroll). Nothing is signed until the proof of possession has
// verified: before that the caller is nobody, and a signature would vouch for
// a stranger's request. Failures before it are bodyless and unsigned (the
// agent sees a transport error); after it, errors are sealed to the agent's
// reply key and signed.
func (a *agentAPI) enroll(w http.ResponseWriter, r *http.Request) {
	now := a.clock()
	helloID := r.Header.Get(agentproto.HeaderEnrollHello)
	if helloID == "" {
		a.reject(w, http.StatusUnauthorized, agentproto.ErrCodeAuth) // the legacy token body, or no exchange at all
		return
	}
	body, ok := a.readBody(w, r, 64<<10)
	if !ok {
		return
	}
	priv, ok := a.hellos.take(helloID, now)
	if !ok {
		a.reject(w, http.StatusUnauthorized, agentproto.ErrCodeSession)
		return
	}
	pt, err := agentproto.HPKEOpen(priv, agentproto.SealInfo(agentproto.DirC2S, agentproto.PathEnroll, helloID), body)
	if err != nil {
		a.reject(w, http.StatusBadRequest, "seal")
		return
	}
	var sub agentproto.EnrollSubmit
	if err := json.Unmarshal(pt, &sub); err != nil {
		a.reject(w, http.StatusBadRequest, "body")
		return
	}
	reply, err := parseP256(sub.Reply)
	if err != nil {
		a.reject(w, http.StatusBadRequest, "reply")
		return
	}
	if d := now.Sub(time.Unix(sub.Created, 0)); d > nonceSkew || d < -nonceSkew {
		a.reject(w, http.StatusUnauthorized, agentproto.ErrCodeStale)
		return
	}
	lookup, err := base64.RawURLEncoding.DecodeString(sub.LookupID)
	csrDER, cerr := agentproto.CSRDER(sub.CSR)
	if err != nil || cerr != nil || len(sub.Nonce) < 16 || len(sub.Nonce) > 64 {
		a.reject(w, http.StatusBadRequest, "body")
		return
	}
	tok, err := a.d.Agents.EnrollTokenByLookup(r.Context(), lookup)
	if err != nil {
		a.rejectErr(w, err, "")
		return
	}
	verified := false
	for _, au := range a.authorities(r.Context()) {
		if agentproto.VerifyPop(sub.Pop, tok.Hash, csrDER, au, sub.Created, sub.Nonce, sub.Reply) {
			verified = true
			break
		}
	}
	if !verified {
		a.reject(w, http.StatusUnauthorized, agentproto.ErrCodeAuth)
		return
	}
	// The proof holds: from here the reply is sealed to the verified key and signed.
	if fresh, nerr := a.nonces.Add("enrol|"+sub.LookupID+"|"+sub.Nonce, now); errors.Is(nerr, errNonceFull) {
		a.d.Log.Error("agent replay cache full; refusing signed requests until entries expire")
		w.Header().Set("Retry-After", "5")
		a.reject(w, http.StatusServiceUnavailable, "busy")
		return
	} else if nerr != nil || !fresh {
		a.sealedReply(w, http.StatusUnauthorized, agentproto.PathEnroll, helloID, reply, map[string]any{"title": "Unauthorized", "status": http.StatusUnauthorized, "detail": "This enrolment request was already seen."})
		return
	}
	acc, err := a.d.Agents.SubmitEnrollment(r.Context(), tok, sub.CSR, sub.Facts, audit.IPFrom(r.Context()))
	if err != nil {
		a.sealedErr(w, err, agentproto.PathEnroll, helloID, reply)
		return
	}
	a.sealedReply(w, http.StatusOK, agentproto.PathEnroll, helloID, reply, acc)
}

// enrollPoll is POST /agent/v1/enroll/{id}: signed by the key of the request's
// CSR (so the poll secret alone is useless), answered sealed to a fresh agent
// ephemeral key and signed. Once approved the answer carries the certificate.
func (a *agentAPI) enrollPoll(w http.ResponseWriter, r *http.Request) {
	now := a.clock()
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		a.reject(w, http.StatusNotFound, agentproto.ErrCodeAuth)
		return
	}
	body, ok := a.readBody(w, r, 4<<10)
	if !ok {
		return
	}
	pub, err := a.d.Agents.EnrollmentKey(r.Context(), id)
	if err != nil {
		a.rejectErr(w, err, "")
		return
	}
	p, err := a.verify(r, body, now, func(keyID string) (*ecdsa.PublicKey, error) {
		if keyID != id.String() {
			return nil, agentproto.ErrSig
		}
		return pub, nil
	})
	if err != nil {
		a.reject(w, http.StatusUnauthorized, errCode(err))
		return
	}
	if !a.checkFresh(w, p, now) {
		return
	}
	reply, err := parseP256(p.Ephemeral)
	if err != nil {
		a.refuse(w, http.StatusBadRequest, "ephemeral", p.Nonce)
		return
	}
	var req agentproto.EnrollPollRequest
	if err := json.Unmarshal(body, &req); err != nil {
		a.sealedReply(w, http.StatusBadRequest, r.URL.Path, p.Nonce, reply, map[string]any{"title": "Bad request", "status": http.StatusBadRequest})
		return
	}
	out, err := a.d.Agents.PollEnrollment(r.Context(), id, req.PollSecret)
	if err != nil {
		a.sealedErr(w, err, r.URL.Path, p.Nonce, reply)
		return
	}
	a.sealedReply(w, http.StatusOK, r.URL.Path, p.Nonce, reply, out)
}

func (a *agentAPI) renew(w http.ResponseWriter, r *http.Request) {
	var req agentproto.RenewRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	resp, err := a.d.Agents.Renew(r.Context(), agentClient(r.Context()), req.CSR)
	if err != nil {
		writeAgentErr(w, a.d.Log, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
