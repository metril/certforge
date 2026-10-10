package agentproto

import (
	"strings"
	"testing"
)

func TestLookupIDHidesTokenHash(t *testing.T) {
	th := TokenHash("cf1.x.y.z")
	id := LookupID(th)
	if id != LookupID(th) || id == LookupID(TokenHash("cf1.x.y.w")) {
		t.Fatal("lookup id must be deterministic and token specific")
	}
	if strings.Contains(id, string(th)) || len(LookupIDBytes(th)) != 32 {
		t.Fatal("lookup id leaks or is the wrong size")
	}
	// Domain separation: it is not the token hash itself, nor a bare sha256 of it.
	if string(LookupIDBytes(th)) == string(th) || LookupID(th) == LookupID(LookupIDBytes(th)) {
		t.Fatal("lookup id is not domain separated")
	}
}

func TestEnrollPopBindsEveryInput(t *testing.T) {
	th := TokenHash("cf1.x.y.z")
	csr := []byte("csr-der")
	pop := EnrollPop(th, csr, "cf.example.com:8443", 1000, "nonce-aaaaaaaaaaaaaaaa", "reply-key")
	if !VerifyPop(pop, th, csr, "cf.example.com:8443", 1000, "nonce-aaaaaaaaaaaaaaaa", "reply-key") {
		t.Fatal("honest pop rejected")
	}
	for name, ok := range map[string]bool{
		"other csr":    VerifyPop(pop, th, []byte("other"), "cf.example.com:8443", 1000, "nonce-aaaaaaaaaaaaaaaa", "reply-key"),
		"other host":   VerifyPop(pop, th, csr, "evil.example.com", 1000, "nonce-aaaaaaaaaaaaaaaa", "reply-key"),
		"other time":   VerifyPop(pop, th, csr, "cf.example.com:8443", 1001, "nonce-aaaaaaaaaaaaaaaa", "reply-key"),
		"other nonce":  VerifyPop(pop, th, csr, "cf.example.com:8443", 1000, "nonce-bbbbbbbbbbbbbbbb", "reply-key"),
		"other reply":  VerifyPop(pop, th, csr, "cf.example.com:8443", 1000, "nonce-aaaaaaaaaaaaaaaa", "attacker-key"),
		"other token":  VerifyPop(pop, TokenHash("cf1.x.y.w"), csr, "cf.example.com:8443", 1000, "nonce-aaaaaaaaaaaaaaaa", "reply-key"),
		"empty":        VerifyPop("", th, csr, "cf.example.com:8443", 1000, "nonce-aaaaaaaaaaaaaaaa", "reply-key"),
		"field splice": VerifyPop(EnrollPop(th, csr, "cf.example.com:84", 4431000, "nonce-aaaaaaaaaaaaaaaa", "reply-key"), th, csr, "cf.example.com:8443", 1000, "nonce-aaaaaaaaaaaaaaaa", "reply-key"),
	} {
		if ok {
			t.Errorf("%s verified", name)
		}
	}
}

func TestVerifyCodeDependsOnKeyAndCA(t *testing.T) {
	a := VerifyCode([]byte("pub-a"), strings.Repeat("a", 64))
	if len(a) != 8 || a != strings.ToUpper(a) {
		t.Fatalf("code %q", a)
	}
	if a != VerifyCode([]byte("pub-a"), strings.Repeat("a", 64)) {
		t.Fatal("not deterministic")
	}
	if a == VerifyCode([]byte("pub-b"), strings.Repeat("a", 64)) || a == VerifyCode([]byte("pub-a"), strings.Repeat("b", 64)) {
		t.Fatal("a different key or CA must change the code")
	}
	if got := FormatVerifyCode("ABCDEFGH"); got != "ABCD-EFGH" {
		t.Fatalf("format %q", got)
	}
}
