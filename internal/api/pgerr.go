package api

import (
	"fmt"
	"net/http"
)

// conflict builds a 409 HTTPError.
func conflict(format string, a ...any) error {
	return &HTTPError{Status: http.StatusConflict, Title: "Conflict", Detail: fmt.Sprintf(format, a...)}
}
