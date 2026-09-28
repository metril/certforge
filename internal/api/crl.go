package api

import (
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/metril/certforge/internal/issuance"
)

// crlTail matches the tail of GET /crl/<tail> for both public CRL routes:
// GET /crl/{caId}.crl (the current issuer) and
// GET /crl/{caId}/{issuerSerial}.crl (any issuer the CA has held), issuer
// serial as lower-case hex (Shared contract: ^[0-9a-f]{1,40}$). A wildcard
// route (like wellKnownACMEChallenge's) rather than chi's own {caId}.crl
// segment syntax, so an id or serial containing an unexpected character
// falls through to this single, explicit regexp instead of chi's own
// routing rules deciding what counts as a match.
var crlTail = regexp.MustCompile(`^([^/]+?)(?:/([0-9a-f]{1,40}))?\.crl$`)

// crlCacheTTL bounds how long a built CRL is served from memory before the
// next request rebuilds it — the same 10 minutes the response's
// Cache-Control: max-age=600 already asks clients to honour, so a
// revocation is never more stale server-side than it already is
// client-side.
const crlCacheTTL = 10 * time.Minute

type crlCacheEntry struct {
	der     []byte
	builtAt time.Time
}

// crlCache is an in-memory cache of built CRL DER, keyed by
// "caId/issuerSerial/crlNumber" (Shared contract): crl_number is bumped on
// every revocation (issuance.caRecorder.Revoke), so the key itself changes
// the instant a revocation commits — a stale entry under the previous key
// is simply never hit again, and ages out under crlCacheTTL like any other
// unused entry, rather than needing to be found and invalidated. Safe for
// concurrent use.
type crlCache struct {
	mu      sync.Mutex
	entries map[string]crlCacheEntry
}

func newCRLCache() *crlCache { return &crlCache{entries: map[string]crlCacheEntry{}} }

func (c *crlCache) get(key string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok || time.Since(e.builtAt) > crlCacheTTL {
		return nil, false
	}
	return e.der, true
}

func (c *crlCache) put(key string, der []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[key] = crlCacheEntry{der: der, builtAt: time.Now()}
}

// crlHandler serves GET /crl/{caId}.crl and GET /crl/{caId}/{issuerSerial}.crl:
// unauthenticated, application/pkix-crl DER (Shared contract's public
// routes). 404 for an unknown id, a non-localca CA, crl: false, or an
// unknown issuer serial — issuance.Store.CRL never distinguishes those
// reasons, so a probing client learns nothing from the response.
func crlHandler(store *issuance.Store, cache *crlCache) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m := crlTail.FindStringSubmatch(chi.URLParam(r, "*"))
		if m == nil {
			http.NotFound(w, r)
			return
		}
		caID, err := uuid.Parse(m[1])
		if err != nil {
			http.NotFound(w, r)
			return
		}
		issuerSerial := m[2]

		// CACRLNumber is a single cheap column read; its own error (an
		// unknown id, most likely) just means no cache key is safe to
		// build, so this falls straight through to store.CRL below, which
		// answers the actual 404.
		var key string
		if n, nErr := store.CACRLNumber(r.Context(), caID); nErr == nil {
			key = caID.String() + "/" + issuerSerial + "/" + strconv.FormatInt(n, 10)
		}
		der, ok := cache.get(key)
		if key == "" || !ok {
			var crlErr error
			if der, crlErr = store.CRL(r.Context(), caID, issuerSerial); crlErr != nil {
				http.NotFound(w, r)
				return
			}
			if key != "" {
				cache.put(key, der)
			}
		}
		w.Header().Set("Content-Type", "application/pkix-crl")
		w.Header().Set("Cache-Control", "max-age=600")
		_, _ = w.Write(der)
	}
}
