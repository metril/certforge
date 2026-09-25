package api

import (
	"net/http"

	"github.com/metril/certforge/internal/agentproto"
)

func (a *agentAPI) enroll(w http.ResponseWriter, r *http.Request) {
	var req agentproto.EnrollRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	resp, err := a.d.Agents.Enroll(r.Context(), req)
	if err != nil {
		writeAgentErr(w, a.d.Log, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
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
