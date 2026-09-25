package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
)

func (a *agentAPI) assignments(w http.ResponseWriter, r *http.Request) {
	out, err := a.d.Agents.Assignments(r.Context(), agentClient(r.Context()))
	if err != nil {
		writeAgentErr(w, a.d.Log, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *agentAPI) bundle(w http.ResponseWriter, r *http.Request) {
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		Write(w, http.StatusNotFound, "Not found", "")
		return
	}
	out, err := a.d.Agents.Bundle(r.Context(), agentClient(r.Context()), id)
	if err != nil {
		writeAgentErr(w, a.d.Log, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, out)
}

func (a *agentAPI) report(w http.ResponseWriter, r *http.Request) {
	var rep agentproto.Report
	if !decodeJSON(w, r, &rep) {
		return
	}
	if err := a.d.Agents.Report(r.Context(), agentClient(r.Context()), rep); err != nil {
		writeAgentErr(w, a.d.Log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *agentAPI) heartbeat(w http.ResponseWriter, r *http.Request) {
	var hb agentproto.Heartbeat
	if !decodeJSON(w, r, &hb) {
		return
	}
	if err := a.d.Agents.Heartbeat(r.Context(), agentClient(r.Context()), hb); err != nil {
		writeAgentErr(w, a.d.Log, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
