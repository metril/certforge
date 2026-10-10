package agentproto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// Directions label each half of a session; they feed both the HKDF info and
// the AAD, so a frame can never be replayed in the opposite direction.
const (
	DirC2S = "c2s"
	DirS2C = "s2c"
)

const sessionLabel = "certforge-agent-session-v1 "

// ErrSeal means a sealed message did not authenticate.
var ErrSeal = errors.New("agentproto: cannot open sealed message")

// SealInfo is the HPKE info for the one-off enrol exchange: it binds the
// direction, the request path and the request nonce.
func SealInfo(dir, path, reqNonce string) []byte {
	return []byte("certforge-agent-hpke-v1\x00" + dir + "\x00" + path + "\x00" + reqNonce)
}

// HPKESeal encrypts plaintext to pub (single shot, RFC 9180 base mode with
// DHKEM(P-256), HKDF-SHA256 and AES-256-GCM). The result is enc || ciphertext.
func HPKESeal(pub *ecdh.PublicKey, info, plaintext []byte) ([]byte, error) {
	pk, err := hpke.NewDHKEMPublicKey(pub)
	if err != nil {
		return nil, err
	}
	return hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), info, plaintext)
}

// HPKEOpen reverses HPKESeal.
func HPKEOpen(priv *ecdh.PrivateKey, info, sealed []byte) ([]byte, error) {
	sk, err := hpke.NewDHKEMPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pt, err := hpke.Open(sk, hpke.HKDFSHA256(), hpke.AES256GCM(), info, sealed)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrSeal, err)
	}
	return pt, nil
}

// Session holds the two per-direction AES-256-GCM keys of one handshake. The
// keys come from ECDH between two ephemeral P-256 keys, so discarding them at
// session end gives forward secrecy; the callers' static keys only sign.
type Session struct {
	sendDir, recvDir string
	send, recv       cipher.AEAD
}

// NewSession derives a session from the local ephemeral private key, the
// peer's ephemeral public key and the session nonce (the HKDF salt). client
// selects which direction is used to send.
func NewSession(local *ecdh.PrivateKey, peer *ecdh.PublicKey, nonce []byte, client bool) (*Session, error) {
	secret, err := local.ECDH(peer)
	if err != nil {
		return nil, err
	}
	aead := func(dir string) (cipher.AEAD, error) {
		k, err := hkdf.Key(sha256.New, secret, nonce, sessionLabel+dir, 32)
		if err != nil {
			return nil, err
		}
		b, err := aes.NewCipher(k)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(b)
	}
	c2s, err := aead(DirC2S)
	if err != nil {
		return nil, err
	}
	s2c, err := aead(DirS2C)
	if err != nil {
		return nil, err
	}
	if client {
		return &Session{DirC2S, DirS2C, c2s, s2c}, nil
	}
	return &Session{DirS2C, DirC2S, s2c, c2s}, nil
}

func seqNonce(seq uint64) []byte {
	n := make([]byte, 12) // 96-bit nonce: 4 zero bytes then the big-endian seq
	binary.BigEndian.PutUint64(n[4:], seq)
	return n
}

func aad(dir string, seq uint64, extra []byte) []byte {
	a := append([]byte(dir), 0)
	a = binary.BigEndian.AppendUint64(a, seq)
	return append(a, extra...)
}

// Seal encrypts plaintext for the peer. Each seq may be used once per
// direction; extra is additional authenticated data (path, request nonce...).
func (s *Session) Seal(seq uint64, plaintext, extra []byte) []byte {
	return s.send.Seal(nil, seqNonce(seq), plaintext, aad(s.sendDir, seq, extra))
}

// Open decrypts a message the peer sealed with the same seq and extra.
func (s *Session) Open(seq uint64, ciphertext, extra []byte) ([]byte, error) {
	pt, err := s.recv.Open(nil, seqNonce(seq), ciphertext, aad(s.recvDir, seq, extra))
	if err != nil {
		return nil, ErrSeal
	}
	return pt, nil
}
