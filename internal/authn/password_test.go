package authn

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	h, err := HashPassword("correct horse battery")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=65536,t=3,p=2$") {
		t.Fatalf("hash %q", h)
	}
	if ok, err := VerifyPassword(h, "correct horse battery"); err != nil || !ok {
		t.Fatalf("ok %v err %v", ok, err)
	}
	if ok, _ := VerifyPassword(h, "wrong horse battery"); ok {
		t.Fatal("wrong password accepted")
	}
	h2, _ := HashPassword("correct horse battery")
	if h == h2 {
		t.Fatal("salt not random")
	}
}

func TestVerifyMalformed(t *testing.T) {
	for _, enc := range []string{
		"",
		"plain",
		"$argon2i$v=19$m=1,t=1,p=1$AAAA$AAAA",
		"$argon2id$v=18$m=65536,t=3,p=2$AAAA$AAAA",
		"$argon2id$v=19$m=x$AAAA$AAAA",
		"$argon2id$v=19$m=65536,t=3,p=2$!!$AAAA",
		"$argon2id$v=19$m=0,t=3,p=2$AAAA$AAAA",
	} {
		if _, err := VerifyPassword(enc, "pw"); err == nil {
			t.Fatalf("%q accepted", enc)
		}
	}
}
