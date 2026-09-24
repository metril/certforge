package api

import (
	"context"
	"fmt"
	"net/http"

	strictnethttp "github.com/oapi-codegen/runtime/strictmiddleware/nethttp"

	"github.com/metril/certforge/internal/audit"
)

type httpCtxKey struct{}

type httpPair struct {
	w http.ResponseWriter
	r *http.Request
}

// withHTTP exposes the raw writer and request to strict handlers (cookies, TLS).
func withHTTP(f strictnethttp.StrictHTTPHandlerFunc, _ string) strictnethttp.StrictHTTPHandlerFunc {
	return func(ctx context.Context, w http.ResponseWriter, r *http.Request, req interface{}) (interface{}, error) {
		return f(context.WithValue(ctx, httpCtxKey{}, httpPair{w: w, r: r}), w, r, req)
	}
}

func httpFrom(ctx context.Context) (http.ResponseWriter, *http.Request) {
	p, _ := ctx.Value(httpCtxKey{}).(httpPair)
	return p.w, p.r
}

// audit records e and logs (does not fail the request) on error.
func (s *Server) audit(ctx context.Context, e audit.Event) {
	if err := s.d.Auditor.Record(ctx, e); err != nil {
		s.d.Log.Error("audit record failed", "action", e.Action, "err", err)
	}
}

func badRequest(format string, a ...any) error {
	return &HTTPError{Status: http.StatusBadRequest, Title: "Bad request", Detail: fmt.Sprintf(format, a...)}
}

func notFound(format string, a ...any) error {
	return &HTTPError{Status: http.StatusNotFound, Title: "Not found", Detail: fmt.Sprintf(format, a...)}
}
