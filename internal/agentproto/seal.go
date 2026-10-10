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
	"sync"
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

// SessionMaxMessages caps each direction of a session; with the 10 minute
// lifetime it bounds how much one key protects, and keeps seq far from wrapping.
const SessionMaxMessages = 1000

// replayWindow is how far behind the highest seq an out-of-order message is
// still accepted.
const replayWindow = 64

// Errors.
var (
	ErrSessionExhausted = errors.New("agentproto: session message limit reached")
	ErrReplay           = errors.New("agentproto: replayed, reordered or out-of-window message")
)

// Session holds the two per-direction AES-256-GCM keys of one handshake. The
// keys come from ECDH between two ephemeral P-256 keys, so discarding them at
// session end gives forward secrecy; the callers' static keys only sign.
// The session owns the send counter (so a nonce is never reused) and tracks
// received seqs (so a frame is never accepted twice).
type Session struct {
	sendDir, recvDir string
	send, recv       cipher.AEAD

	mu       sync.Mutex
	sendSeq  uint64
	recvNext uint64 // OpenInOrder: the only seq accepted next
	recvHi   uint64 // OpenWindow: highest authenticated seq
	recvBits uint64 // bit i set: seq recvHi-i was seen
	recvAny  bool
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
		return &Session{sendDir: DirC2S, recvDir: DirS2C, send: c2s, recv: s2c}, nil
	}
	return &Session{sendDir: DirS2C, recvDir: DirC2S, send: s2c, recv: c2s}, nil
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

// Seal encrypts plaintext for the peer under the next seq, which it returns
// for the peer's nonce and AAD. extra is additional authenticated data (path,
// request nonce...). It fails with ErrSessionExhausted after
// SessionMaxMessages messages: the caller must start a new session.
func (s *Session) Seal(plaintext, extra []byte) (uint64, []byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sendSeq >= SessionMaxMessages {
		return 0, nil, ErrSessionExhausted
	}
	seq := s.sendSeq
	s.sendSeq++
	return seq, s.send.Seal(nil, seqNonce(seq), plaintext, aad(s.sendDir, seq, extra)), nil
}

func (s *Session) open(seq uint64, ct, extra []byte) ([]byte, error) {
	pt, err := s.recv.Open(nil, seqNonce(seq), ct, aad(s.recvDir, seq, extra))
	if err != nil {
		return nil, ErrSeal
	}
	return pt, nil
}

// OpenInOrder decrypts the next message of a strictly ordered stream (the
// WebSocket): seq must be exactly one past the last accepted one.
func (s *Session) OpenInOrder(seq uint64, ct, extra []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq != s.recvNext || seq >= SessionMaxMessages {
		return nil, ErrReplay
	}
	pt, err := s.open(seq, ct, extra)
	if err == nil {
		s.recvNext++
	}
	return pt, err
}

// OpenWindow decrypts a message that may arrive out of order (concurrent
// REST requests): a seq already seen, or more than 64 behind the highest
// authenticated one, is refused. Only messages that authenticate are recorded.
func (s *Session) OpenWindow(seq uint64, ct, extra []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if seq >= SessionMaxMessages {
		return nil, ErrReplay
	}
	if s.recvAny && seq <= s.recvHi {
		if d := s.recvHi - seq; d >= replayWindow || s.recvBits&(1<<d) != 0 {
			return nil, ErrReplay
		}
	}
	pt, err := s.open(seq, ct, extra)
	if err != nil {
		return nil, err
	}
	switch {
	case !s.recvAny:
		s.recvHi, s.recvBits, s.recvAny = seq, 1, true
	case seq > s.recvHi:
		if d := seq - s.recvHi; d >= replayWindow {
			s.recvBits = 1
		} else {
			s.recvBits = s.recvBits<<d | 1
		}
		s.recvHi = seq
	default:
		s.recvBits |= 1 << (s.recvHi - seq)
	}
	return pt, nil
}
