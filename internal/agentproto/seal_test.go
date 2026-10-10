package agentproto

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
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

func mustSeal(t *testing.T, s *Session, pt, extra string) (uint64, []byte) {
	t.Helper()
	seq, ct, err := s.Seal([]byte(pt), []byte(extra))
	if err != nil {
		t.Fatal(err)
	}
	return seq, ct
}

func TestSessionRoundTripBothDirections(t *testing.T) {
	cli, srv := sessionPair(t)
	seq, ct := mustSeal(t, cli, "hello", "/p")
	if pt, err := srv.OpenInOrder(seq, ct, []byte("/p")); err != nil || string(pt) != "hello" {
		t.Fatalf("%q %v", pt, err)
	}
	seq, ct = mustSeal(t, srv, "world", "")
	if pt, err := cli.OpenWindow(seq, ct, nil); err != nil || string(pt) != "world" {
		t.Fatalf("%q %v", pt, err)
	}
}

func TestSessionSealNeverReusesSeq(t *testing.T) {
	cli, _ := sessionPair(t)
	a, _ := mustSeal(t, cli, "x", "")
	b, _ := mustSeal(t, cli, "x", "")
	if a == b || b != a+1 {
		t.Fatalf("seqs %d %d", a, b)
	}
}

func TestSessionSealRefusesPastCap(t *testing.T) {
	cli, _ := sessionPair(t)
	for i := 0; i < SessionMaxMessages; i++ {
		if _, _, err := cli.Seal(nil, nil); err != nil {
			t.Fatalf("seal %d: %v", i, err)
		}
	}
	if _, _, err := cli.Seal(nil, nil); !errors.Is(err, ErrSessionExhausted) {
		t.Fatalf("err %v", err)
	}
	cli.sendSeq = ^uint64(0) // a wrapped counter is refused too
	if _, _, err := cli.Seal(nil, nil); !errors.Is(err, ErrSessionExhausted) {
		t.Fatalf("wrap err %v", err)
	}
}

func TestSessionOpenRejectsTamperReflectionAndWrongKeys(t *testing.T) {
	cli, srv := sessionPair(t)
	seq, ct := mustSeal(t, cli, "x", "a")
	if _, err := srv.OpenWindow(seq, ct, []byte("b")); err == nil {
		t.Error("wrong aad")
	}
	if _, err := cli.OpenWindow(seq, ct, []byte("a")); err == nil {
		t.Error("reflected into own direction")
	}
	bad := bytes.Clone(ct)
	bad[0] ^= 1
	if _, err := srv.OpenWindow(seq, bad, []byte("a")); err == nil {
		t.Error("tampered")
	}
	// failed attempts must not burn the seq
	if pt, err := srv.OpenWindow(seq, ct, []byte("a")); err != nil || string(pt) != "x" {
		t.Fatalf("genuine message refused after failures: %v", err)
	}
	o, err := NewSession(p256(t), p256(t).PublicKey(), []byte("session-nonce"), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := o.OpenWindow(seq, ct, []byte("a")); err == nil {
		t.Error("wrong keys")
	}
	a, b := p256(t), p256(t)
	s1, _ := NewSession(a, b.PublicKey(), []byte("n1"), true)
	s2, _ := NewSession(b, a.PublicKey(), []byte("n2"), false)
	sq, c := mustSeal(t, s1, "x", "")
	if _, err := s2.OpenWindow(sq, c, nil); err == nil {
		t.Error("different session nonce")
	}
}

func TestOpenInOrder(t *testing.T) {
	cli, srv := sessionPair(t)
	s0, c0 := mustSeal(t, cli, "0", "")
	s1, c1 := mustSeal(t, cli, "1", "")
	s2, c2 := mustSeal(t, cli, "2", "")
	if _, err := srv.OpenInOrder(s1, c1, nil); !errors.Is(err, ErrReplay) {
		t.Errorf("skipped ahead: %v", err)
	}
	if _, err := srv.OpenInOrder(s0, c0, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.OpenInOrder(s0, c0, nil); !errors.Is(err, ErrReplay) {
		t.Errorf("duplicate: %v", err)
	}
	if _, err := srv.OpenInOrder(s2, c2, nil); !errors.Is(err, ErrReplay) {
		t.Errorf("reordered: %v", err)
	}
	if _, err := srv.OpenInOrder(s1, c1, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.OpenInOrder(s2, c2, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.OpenInOrder(SessionMaxMessages, c2, nil); !errors.Is(err, ErrReplay) {
		t.Errorf("past cap: %v", err)
	}
}

func TestOpenWindow(t *testing.T) {
	cli, srv := sessionPair(t)
	type msg struct {
		seq uint64
		ct  []byte
	}
	var ms []msg
	for i := 0; i < 200; i++ {
		s, c := mustSeal(t, cli, "m", "")
		ms = append(ms, msg{s, c})
	}
	open := func(i int) error { _, err := srv.OpenWindow(ms[i].seq, ms[i].ct, nil); return err }
	for _, i := range []int{5, 3, 4, 0} { // out of order inside the window
		if err := open(i); err != nil {
			t.Fatalf("msg %d: %v", i, err)
		}
	}
	for _, i := range []int{5, 3, 0} {
		if err := open(i); !errors.Is(err, ErrReplay) {
			t.Errorf("duplicate %d: %v", i, err)
		}
	}
	if err := open(130); err != nil { // jumps ahead; 0..5 now fall out of the window
		t.Fatal(err)
	}
	if err := open(1); !errors.Is(err, ErrReplay) {
		t.Errorf("out of window: %v", err)
	}
	if err := open(130 - 63); err != nil {
		t.Errorf("window edge: %v", err)
	}
	if err := open(130 - 64); !errors.Is(err, ErrReplay) {
		t.Errorf("just outside window: %v", err)
	}
	if _, err := srv.OpenWindow(SessionMaxMessages, ms[0].ct, nil); !errors.Is(err, ErrReplay) {
		t.Errorf("past cap: %v", err)
	}
}
