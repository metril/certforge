package api

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/signer"
)

// mapErr turns issuance domain errors into problem responses; anything else
// stays an internal error. A rename that fails issuance.Store's RenameHook
// (agents.Service.ResyncCertificateRename, an overlapping-path conflict)
// surfaces as *agents.Error here too, mapped the same way mapAgentErr maps it.
func mapErr(err error) error {
	var ve *issuance.ValidationError
	var iu *issuance.InUseError
	var ce *issuance.ConflictError
	var se *signer.Error
	var ae *agents.Error
	switch {
	case err == nil:
		return nil
	case errors.Is(err, issuance.ErrNotFound), errors.Is(err, certstore.ErrNotFound):
		return &HTTPError{Status: http.StatusNotFound, Title: "Not found", Detail: err.Error()}
	case errors.As(err, &ve):
		return &HTTPError{Status: http.StatusUnprocessableEntity, Title: "Invalid " + ve.Field, Detail: ve.Msg}
	case errors.As(err, &iu):
		return &HTTPError{Status: http.StatusConflict, Title: "In use", Detail: iu.Error()}
	case errors.As(err, &ce):
		return &HTTPError{Status: http.StatusConflict, Title: "Conflict", Detail: ce.Msg}
	case errors.As(err, &se):
		return &HTTPError{Status: http.StatusBadGateway, Title: "CA error", Detail: se.Error()}
	case errors.As(err, &ae):
		return mapAgentErr(err)
	}
	return err
}

func unprocessable(field, detail string) error {
	return &HTTPError{Status: http.StatusUnprocessableEntity, Title: "Invalid " + field, Detail: detail}
}

// convert copies between types with identical JSON shapes (domain <-> gen).
func convert[T any](in any) (T, error) {
	var out T
	b, err := json.Marshal(in)
	if err != nil {
		return out, err
	}
	err = json.Unmarshal(b, &out)
	return out, err
}

func ptr[T any](v T) *T { return &v }

// certSortFields are the values ?sort= accepts (without a leading "-").
var certSortFields = []string{"name", "notAfter", "nextRenewAt", "status"}

// certCursor is the opaque nextCursor/?cursor= payload: base64url JSON. It
// binds to the exact status/q/sort/desc of the request it was issued for —
// decodeCertCursor rejects a cursor whose bound params differ from the
// current request, not just one that fails to parse — because a keyset
// cursor names a specific row in a specific ordering: replaying it against
// a different filter or sort would silently resume from the wrong place.
type certCursor struct {
	Sort    string    `json:"sort"`
	Desc    bool      `json:"desc"`
	Q       string    `json:"q"`
	Status  string    `json:"status"`
	LastKey string    `json:"lastKey"`
	LastID  uuid.UUID `json:"lastId"`
}

func encodeCertCursor(c certCursor) string {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err) // certCursor always marshals
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func decodeCertCursor(s, status, q, sort string, desc bool) (*certCursor, error) {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, unprocessable("cursor", "cursor is not from this list")
	}
	var c certCursor
	if err := json.Unmarshal(b, &c); err != nil {
		return nil, unprocessable("cursor", "cursor is not from this list")
	}
	if c.Status != status || c.Q != q || c.Sort != sort || c.Desc != desc {
		return nil, unprocessable("cursor", "cursor does not match this request's status, q, or sort")
	}
	return &c, nil
}

// certListParams is one page's parsed and validated
// ?status=&q=&sort=&limit=&cursor= request.
type certListParams struct {
	status string // "" = no filter
	q      string // "" = no filter; lower-cased, trimmed
	sort   string // canonical sort field, no leading "-"
	desc   bool
	limit  int
	cursor *certCursor // nil = first page
}

// parseCertList validates and normalizes the certificate list's query
// parameters. Sorting and filtering happen in the store (SQL), not here;
// this only validates shape and, for a cursor, that it matches the rest of
// the request.
func parseCertList(status, q, sort *string, limit *int, cursor *string) (certListParams, error) {
	p := certListParams{limit: 50, sort: "name"}
	if status != nil {
		p.status = *status
	}
	if q != nil {
		p.q = strings.ToLower(strings.TrimSpace(*q))
	}
	raw := "name"
	if sort != nil && *sort != "" {
		raw = *sort
	}
	p.desc = strings.HasPrefix(raw, "-")
	p.sort = strings.TrimPrefix(raw, "-")
	if !slices.Contains(certSortFields, p.sort) {
		names := append([]string(nil), certSortFields...)
		slices.Sort(names)
		return p, unprocessable("sort", "sort by one of "+strings.Join(names, ", "))
	}
	if limit != nil {
		if *limit < 1 || *limit > 500 {
			return p, unprocessable("limit", "limit must be 1..500")
		}
		p.limit = *limit
	}
	if cursor != nil && *cursor != "" {
		c, err := decodeCertCursor(*cursor, p.status, p.q, p.sort, p.desc)
		if err != nil {
			return p, err
		}
		p.cursor = c
	}
	return p, nil
}
