package agentproto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

func p256(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	k, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestHPKERoundTripAndBinding(t *testing.T) {
	k := p256(t)
	info := SealInfo(DirC2S, "/agent/v1/enroll", "n1")
	ct, err := HPKESeal(k.PublicKey(), info, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ct, []byte("secret")) {
		t.Fatal("plaintext leaked")
	}
	if pt, err := HPKEOpen(k, info, ct); err != nil || string(pt) != "secret" {
		t.Fatalf("%q %v", pt, err)
	}
	for name, bad := range map[string][]byte{
		"direction": SealInfo(DirS2C, "/agent/v1/enroll", "n1"),
		"path":      SealInfo(DirC2S, "/agent/v1/other", "n1"),
		"nonce":     SealInfo(DirC2S, "/agent/v1/enroll", "n2"),
	} {
		if _, err := HPKEOpen(k, bad, ct); err == nil {
			t.Errorf("opened with wrong %s", name)
		}
	}
	if _, err := HPKEOpen(p256(t), info, ct); err == nil {
		t.Error("opened with wrong key")
	}
	ct[len(ct)-1] ^= 1
	if _, err := HPKEOpen(k, info, ct); err == nil {
		t.Error("opened tampered ciphertext")
	}
}

func sessionPair(t *testing.T) (cli, srv *Session) {
	t.Helper()
	a, b := p256(t), p256(t)
	nonce := []byte("session-nonce")
	cli, err := NewSession(a, b.PublicKey(), nonce, true)
	if err != nil {
		t.Fatal(err)
	}
	srv, err = NewSession(b, a.PublicKey(), nonce, false)
	if err != nil {
		t.Fatal(err)
	}
	return cli, srv
}

func TestSessionRoundTripBothDirections(t *testing.T) {
	cli, srv := sessionPair(t)
	ct := cli.Seal(1, []byte("hello"), []byte("/p"))
	if pt, err := srv.Open(1, ct, []byte("/p")); err != nil || string(pt) != "hello" {
		t.Fatalf("%q %v", pt, err)
	}
	ct = srv.Seal(1, []byte("world"), nil)
	if pt, err := cli.Open(1, ct, nil); err != nil || string(pt) != "world" {
		t.Fatalf("%q %v", pt, err)
	}
}

func TestSessionRejectsTamperReplayReflectionAndWrongKeys(t *testing.T) {
	cli, srv := sessionPair(t)
	ct := cli.Seal(7, []byte("x"), []byte("a"))
	if _, err := srv.Open(8, ct, []byte("a")); err == nil {
		t.Error("wrong seq")
	}
	if _, err := srv.Open(7, ct, []byte("b")); err == nil {
		t.Error("wrong aad")
	}
	if _, err := cli.Open(7, ct, []byte("a")); err == nil {
		t.Error("reflected into own direction")
	}
	bad := bytes.Clone(ct)
	bad[0] ^= 1
	if _, err := srv.Open(7, bad, []byte("a")); err == nil {
		t.Error("tampered")
	}
	other := p256(t)
	if o, err := NewSession(other, p256(t).PublicKey(), []byte("session-nonce"), false); err != nil {
		t.Fatal(err)
	} else if _, err := o.Open(7, ct, []byte("a")); err == nil {
		t.Error("wrong keys")
	}
	a, b := p256(t), p256(t)
	s1, _ := NewSession(a, b.PublicKey(), []byte("n1"), true)
	s2, _ := NewSession(b, a.PublicKey(), []byte("n2"), false)
	if _, err := s2.Open(1, s1.Seal(1, []byte("x"), nil), nil); err == nil {
		t.Error("different session nonce")
	}
}
