package agentproto

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

const fp = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestTokenRoundTrip(t *testing.T) {
	s, err := NewToken("https://cf.example.test:8443", fp)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, "cf1.") || strings.Count(s, ".") != 3 {
		t.Fatalf("token %q", s)
	}
	tok, err := ParseToken(" " + s + "\n")
	if err != nil {
		t.Fatal(err)
	}
	if tok.AgentURL != "https://cf.example.test:8443" || tok.CAFingerprint != fp || len(tok.Secret) != 43 {
		t.Fatalf("parsed %+v", tok)
	}
	if !bytes.Equal(TokenHash(s), TokenHash(" "+s+" ")) || len(TokenHash(s)) != 32 {
		t.Fatal("hash not stable over surrounding space")
	}
	other, _ := NewToken("https://cf.example.test:8443", fp)
	if other == s {
		t.Fatal("secrets repeat")
	}
}

func TestNewTokenValidatesInputs(t *testing.T) {
	if _, err := NewToken("http://cf.example.test:8443", fp); !errors.Is(err, ErrBadToken) {
		t.Fatalf("http URL: err = %v", err)
	}
	if _, err := NewToken("https://cf.example.test:8443", "XYZ"); !errors.Is(err, ErrBadToken) {
		t.Fatalf("bad fingerprint: err = %v", err)
	}
	if _, err := NewToken("not a url", fp); !errors.Is(err, ErrBadToken) {
		t.Fatalf("garbage URL: err = %v", err)
	}
	// A token NewToken accepts must always round-trip through ParseToken.
	s, err := NewToken("https://cf.example.test:8443", fp)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseToken(s); err != nil {
		t.Fatalf("ParseToken(NewToken(...)) = %v", err)
	}
}

func TestParseTokenRejects(t *testing.T) {
	good, _ := NewToken("https://cf.example.test:8443", fp)
	parts := strings.Split(good, ".")
	for name, s := range map[string]string{
		"prefix":   "cf2." + strings.Join(parts[1:], "."),
		"parts":    strings.Join(parts[:3], "."),
		"http url": "cf1.aHR0cDovL2NmLmV4YW1wbGUudGVzdA." + fp + "." + parts[3],
		"bad fp":   "cf1." + parts[1] + ".XYZ." + parts[3],
		"short":    "cf1." + parts[1] + "." + fp + ".c2hvcnQ",
	} {
		if _, err := ParseToken(s); !errors.Is(err, ErrBadToken) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}
