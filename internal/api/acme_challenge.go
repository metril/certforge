package api

import (
	"net/http"
	"regexp"

	"github.com/go-chi/chi/v5"

	"github.com/metril/certforge/internal/challenge"
)

// wellKnownToken matches a valid http-01 token: the base64url alphabet
// RFC 8555 §8.3 draws tokens from, capped well above any real token length.
// Anything else — including a "." or "/", which the wildcard route below
// also lets through as part of the URL tail — is rejected the same as an
// unknown token (404), so a scanner probing the path learns nothing from
// the response.
var wellKnownToken = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// wellKnownACMEChallenge serves GET /.well-known/acme-challenge/{token}: the
// http-01 key authorization for a token this server itself is serving
// (challenge.HTTPTokens, server-side http-01; see NewServerHTTP01).
// Unauthenticated by design (RFC 8555 has no concept of a session here);
// mounted on the main listener outside /api/v1 and not in the OpenAPI
// document (documented in docs/api.md instead).
func wellKnownACMEChallenge(tokens *challenge.HTTPTokens) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := chi.URLParam(r, "*")
		if tokens == nil || !wellKnownToken.MatchString(token) {
			http.NotFound(w, r)
			return
		}
		keyAuth, ok := tokens.Get(token)
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte(keyAuth))
	}
}
