package agentproto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"
)

func TestHelloAckSignatureBindsEverything(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	now := time.Now()
	ack := HelloAck{Ephemeral: "server-eph", Session: "sess"}
	if err := SignHelloAck(&ack, key, "agent-eph", "nonce1", now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyHelloAck(ack, &key.PublicKey, "agent-eph", "nonce1", now); err != nil {
		t.Fatal(err)
	}
	for name, f := range map[string]func() error{
		"server key": func() error {
			a := ack
			a.Ephemeral = "x"
			return VerifyHelloAck(a, &key.PublicKey, "agent-eph", "nonce1", now)
		},
		"session": func() error {
			a := ack
			a.Session = "x"
			return VerifyHelloAck(a, &key.PublicKey, "agent-eph", "nonce1", now)
		},
		"agent key":     func() error { return VerifyHelloAck(ack, &key.PublicKey, "x", "nonce1", now) },
		"upgrade nonce": func() error { return VerifyHelloAck(ack, &key.PublicKey, "agent-eph", "nonce2", now) },
		"signer":        func() error { return VerifyHelloAck(ack, &other.PublicKey, "agent-eph", "nonce1", now) },
		"stale":         func() error { return VerifyHelloAck(ack, &key.PublicKey, "agent-eph", "nonce1", now.Add(time.Hour)) },
		"unsigned": func() error {
			return VerifyHelloAck(HelloAck{Ephemeral: "server-eph", Session: "sess"}, &key.PublicKey, "agent-eph", "nonce1", now)
		},
	} {
		if f() == nil {
			t.Errorf("a hello_ack with a changed %s verified", name)
		}
	}
}
