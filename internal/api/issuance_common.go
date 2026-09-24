package api

import (
	"cmp"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/metril/certforge/internal/certstore"
	"github.com/metril/certforge/internal/issuance"
	"github.com/metril/certforge/internal/signer"
)

// mapErr turns issuance domain errors into problem responses; anything else
// stays an internal error.
func mapErr(err error) error {
	var ve *issuance.ValidationError
	var iu *issuance.InUseError
	var se *signer.Error
	switch {
	case err == nil:
		return nil
	case errors.Is(err, issuance.ErrNotFound), errors.Is(err, certstore.ErrNotFound):
		return &HTTPError{Status: http.StatusNotFound, Title: "Not found", Detail: err.Error()}
	case errors.As(err, &ve):
		return &HTTPError{Status: http.StatusUnprocessableEntity, Title: "Invalid " + ve.Field, Detail: ve.Msg}
	case errors.As(err, &iu):
		return &HTTPError{Status: http.StatusConflict, Title: "In use", Detail: iu.Error()}
	case errors.As(err, &se):
		return &HTTPError{Status: http.StatusBadGateway, Title: "CA error", Detail: se.Error()}
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

// listParams are ?status=&q=&sort=&limit=&cursor= for paged lists.
type listParams struct {
	status, q, sort string
	limit, offset   int
}

// parseList validates and normalizes the standard list query parameters.
func parseList(status, q, sort *string, limit *int, cursor *string) (listParams, error) {
	p := listParams{limit: 50}
	if status != nil {
		p.status = *status
	}
	if q != nil {
		p.q = strings.ToLower(strings.TrimSpace(*q))
	}
	if sort != nil {
		p.sort = *sort
	}
	if limit != nil {
		if *limit < 1 || *limit > 500 {
			return p, unprocessable("limit", "limit must be 1..500")
		}
		p.limit = *limit
	}
	if cursor != nil && *cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(*cursor)
		off, err2 := strconv.Atoi(strings.TrimPrefix(string(b), "o:"))
		if err != nil || err2 != nil || off < 0 {
			return p, unprocessable("cursor", "cursor is not from this list")
		}
		p.offset = off
	}
	return p, nil
}

// matches reports whether the q search hits any field.
//
//nolint:unused // used by Task 14's certificate list handler.
func (p listParams) matches(fields ...string) bool {
	if p.q == "" {
		return true
	}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), p.q) {
			return true
		}
	}
	return false
}

// sortItems sorts by p.sort ("key" or "-key"), def when empty; unknown keys are 422.
func sortItems[T any](items []T, p listParams, def string, keys map[string]func(a, b T) int) error {
	key := p.sort
	if key == "" {
		key = def
	}
	desc := strings.HasPrefix(key, "-")
	cmpFn, ok := keys[strings.TrimPrefix(key, "-")]
	if !ok {
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		slices.Sort(names)
		return unprocessable("sort", "sort by one of "+strings.Join(names, ", "))
	}
	slices.SortStableFunc(items, func(a, b T) int {
		if desc {
			return cmpFn(b, a)
		}
		return cmpFn(a, b)
	})
	return nil
}

// page cuts one page and returns the next cursor (nil on the last page).
func page[T any](items []T, p listParams) ([]T, *string) {
	if p.offset >= len(items) {
		return []T{}, nil
	}
	end := min(p.offset+p.limit, len(items))
	var next *string
	if end < len(items) {
		c := base64.RawURLEncoding.EncodeToString([]byte("o:" + strconv.Itoa(end)))
		next = &c
	}
	return items[p.offset:end], next
}

func byString[T any](f func(T) string) func(a, b T) int {
	return func(a, b T) int { return cmp.Compare(f(a), f(b)) }
}
