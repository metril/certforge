package api

import (
	"errors"
	"net/http"
	"testing"

	"github.com/google/uuid"
)

func problemStatus(err error) int {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status
	}
	return 0
}

func TestParseCertListDefaults(t *testing.T) {
	p, err := parseCertList(nil, nil, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.status != "" || p.q != "" || p.sort != "name" || p.desc || p.limit != 50 || p.cursor != nil {
		t.Fatalf("defaults = %+v", p)
	}
	desc := "-notAfter"
	q := "  Web  "
	p, err = parseCertList(nil, &q, &desc, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if p.sort != "notAfter" || !p.desc || p.q != "web" {
		t.Fatalf("parsed = %+v", p)
	}
}

func TestParseCertListValidation(t *testing.T) {
	bad := "size"
	if _, err := parseCertList(nil, nil, &bad, nil, nil); problemStatus(err) != http.StatusUnprocessableEntity {
		t.Fatalf("unknown sort: %v", err)
	}
	zero := 0
	if _, err := parseCertList(nil, nil, nil, &zero, nil); problemStatus(err) != http.StatusUnprocessableEntity {
		t.Fatalf("limit 0: %v", err)
	}
	tooBig := 501
	if _, err := parseCertList(nil, nil, nil, &tooBig, nil); problemStatus(err) != http.StatusUnprocessableEntity {
		t.Fatalf("limit 501: %v", err)
	}
	junk := "not-base64url-json!!"
	if _, err := parseCertList(nil, nil, nil, nil, &junk); problemStatus(err) != http.StatusUnprocessableEntity {
		t.Fatalf("garbage cursor: %v", err)
	}
}

// TestCertCursorRoundTrip and TestCertCursorMismatch are the Review Focus
// for the cursor's binding to status/q/sort: a cursor decodes only against
// the exact request it was issued for.
func TestCertCursorRoundTrip(t *testing.T) {
	id := uuid.New()
	enc := encodeCertCursor(certCursor{Sort: "name", Desc: false, Q: "web", Status: "active", LastKey: "web-1", LastID: id})
	c, err := decodeCertCursor(enc, "active", "web", "name", false)
	if err != nil {
		t.Fatal(err)
	}
	if c.LastKey != "web-1" || c.LastID != id {
		t.Fatalf("decoded = %+v", c)
	}
}

func TestCertCursorMismatch(t *testing.T) {
	enc := encodeCertCursor(certCursor{Sort: "name", Desc: false, Q: "", Status: "", LastKey: "web-1", LastID: uuid.New()})
	cases := []struct {
		name            string
		status, q, sort string
		desc            bool
	}{
		{"status differs", "active", "", "name", false},
		{"q differs", "", "mail", "name", false},
		{"sort differs", "", "", "notAfter", false},
		{"direction differs", "", "", "name", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := decodeCertCursor(enc, tc.status, tc.q, tc.sort, tc.desc); problemStatus(err) != http.StatusUnprocessableEntity {
				t.Fatalf("%s: want 422, got %v", tc.name, err)
			}
		})
	}
	// A cursor that isn't even valid base64url/JSON is rejected the same way.
	if _, err := decodeCertCursor("!!not-a-cursor!!", "", "", "name", false); problemStatus(err) != http.StatusUnprocessableEntity {
		t.Fatalf("tampered cursor: %v", err)
	}
}
