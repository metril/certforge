package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
)

// Write sends an RFC 9457 problem+json response.
func Write(w http.ResponseWriter, status int, title, detail string) {
	writeProblem(w, status, title, detail, nil)
}

// writeProblem is Write plus extension members, merged into the body.
func writeProblem(w http.ResponseWriter, status int, title, detail string, extra map[string]any) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	body := map[string]any{}
	maps.Copy(body, extra)
	maps.Copy(body, map[string]any{"type": "about:blank", "title": title, "status": status})
	if detail != "" {
		body["detail"] = detail
	}
	_ = json.NewEncoder(w).Encode(body)
}

// HTTPError is returned by handlers to produce a 4xx problem response.
type HTTPError struct {
	Status int
	Title  string
	Detail string
	Extra  map[string]any // extension members added to the problem body
}

func (e *HTTPError) Error() string {
	if e.Detail == "" {
		return fmt.Sprintf("%d %s", e.Status, e.Title)
	}
	return fmt.Sprintf("%d %s: %s", e.Status, e.Title, e.Detail)
}

var errUnauthenticated = &HTTPError{Status: http.StatusUnauthorized, Title: "Authentication required"}

func requestError(w http.ResponseWriter, _ *http.Request, err error) {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		Write(w, http.StatusRequestEntityTooLarge, "Payload too large", fmt.Sprintf("Request body must not exceed %d bytes.", mbe.Limit))
		return
	}
	Write(w, http.StatusBadRequest, "Bad request", err.Error())
}

func (s *Server) responseError(w http.ResponseWriter, r *http.Request, err error) {
	var he *HTTPError
	if errors.As(err, &he) {
		writeProblem(w, he.Status, he.Title, he.Detail, he.Extra)
		return
	}
	s.d.Log.Error("request failed", "method", r.Method, "path", r.URL.Path, "err", err)
	Write(w, http.StatusInternalServerError, "Internal server error", "")
}
