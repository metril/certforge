package agentproto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var sigNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func sigKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func signedReq(t *testing.T, key *ecdsa.PrivateKey, body []byte) (*http.Request, ReqParams) {
	t.Helper()
	r := httptest.NewRequest("POST", "https://certforge.test/agent/v1/sync?a=1", nil)
	p := ReqParams{Authority: "certforge.test", KeyID: "cid:abc1", Nonce: NewNonce(), Created: sigNow, Ephemeral: "ZXBoZW1lcmFs"}
	if err := SignRequest(r, body, key, p); err != nil {
		t.Fatal(err)
	}
	return r, p
}

func lookupOf(pub *ecdsa.PublicKey) func(string) (*ecdsa.PublicKey, error) {
	return func(id string) (*ecdsa.PublicKey, error) {
		if id != "cid:abc1" {
			return nil, errors.New("unknown key")
		}
		return pub, nil
	}
}

func TestRequestSignatureRoundTrip(t *testing.T) {
	key := sigKey(t)
	body := []byte("ciphertext")
	r, p := signedReq(t, key, body)
	got, err := VerifyRequest(r, body, "CertForge.test", sigNow.Add(30*time.Second), lookupOf(&key.PublicKey))
	if err != nil || got.Nonce != p.Nonce || got.KeyID != p.KeyID || got.Ephemeral != p.Ephemeral || !got.Created.Equal(p.Created) {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestRequestSignatureRejectsTampering(t *testing.T) {
	key := sigKey(t)
	body := []byte("ciphertext")
	cases := map[string]func(r *http.Request, b []byte, auth *string, now *time.Time) []byte{
		"body":      func(*http.Request, []byte, *string, *time.Time) []byte { return []byte("other") },
		"method":    func(r *http.Request, b []byte, _ *string, _ *time.Time) []byte { r.Method = "PUT"; return b },
		"path":      func(r *http.Request, b []byte, _ *string, _ *time.Time) []byte { r.URL.Path = "/agent/v1/x"; return b },
		"query":     func(r *http.Request, b []byte, _ *string, _ *time.Time) []byte { r.URL.RawQuery = "a=2"; return b },
		"authority": func(_ *http.Request, b []byte, a *string, _ *time.Time) []byte { *a = "evil.test"; return b },
		"ephemeral": func(r *http.Request, b []byte, _ *string, _ *time.Time) []byte {
			r.Header.Set(HeaderEphemeral, "b3RoZXI")
			return b
		},
		"digest": func(r *http.Request, b []byte, _ *string, _ *time.Time) []byte {
			r.Header.Set(HeaderContentDigest, ContentDigest([]byte("other")))
			return b
		},
		"nonce": func(r *http.Request, b []byte, _ *string, _ *time.Time) []byte {
			r.Header.Set(HeaderSignatureInput, strings.Replace(r.Header.Get(HeaderSignatureInput), `nonce="`, `nonce="x`, 1))
			return b
		},
		"keyid": func(r *http.Request, b []byte, _ *string, _ *time.Time) []byte {
			r.Header.Set(HeaderSignatureInput, strings.Replace(r.Header.Get(HeaderSignatureInput), `abc1`, `abc2`, 1))
			return b
		},
		"created": func(r *http.Request, b []byte, _ *string, _ *time.Time) []byte {
			r.Header.Set(HeaderSignatureInput, strings.Replace(r.Header.Get(HeaderSignatureInput), `created=17`, `created=18`, 1))
			return b
		},
		"extra param": func(r *http.Request, b []byte, _ *string, _ *time.Time) []byte {
			r.Header.Set(HeaderSignatureInput, r.Header.Get(HeaderSignatureInput)+`;x=1`)
			return b
		},
		"missing signature": func(r *http.Request, b []byte, _ *string, _ *time.Time) []byte {
			r.Header.Del(HeaderSignature)
			return b
		},
		"too old": func(_ *http.Request, b []byte, _ *string, n *time.Time) []byte {
			*n = sigNow.Add(MaxSkew + time.Second)
			return b
		},
		"from the future": func(_ *http.Request, b []byte, _ *string, n *time.Time) []byte {
			*n = sigNow.Add(-MaxSkew - time.Second)
			return b
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			r, _ := signedReq(t, key, body)
			auth, now := "certforge.test", sigNow
			b := mutate(r, body, &auth, &now)
			if _, err := VerifyRequest(r, b, auth, now, lookupOf(&key.PublicKey)); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	t.Run("wrong key", func(t *testing.T) {
		r, _ := signedReq(t, key, body)
		if _, err := VerifyRequest(r, body, "certforge.test", sigNow, lookupOf(&sigKey(t).PublicKey)); !errors.Is(err, ErrSig) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("clock error type", func(t *testing.T) {
		r, _ := signedReq(t, key, body)
		if _, err := VerifyRequest(r, body, "certforge.test", sigNow.Add(time.Hour), lookupOf(&key.PublicKey)); !errors.Is(err, ErrStale) {
			t.Fatalf("%v", err)
		}
	})
}

func TestResponseSignature(t *testing.T) {
	key := sigKey(t)
	body := []byte("sealed")
	p := RespParams{KeyID: "srv:01", ReqNonce: "reqn", Created: sigNow}
	h := http.Header{}
	if err := SignResponse(h, 200, body, key, p); err != nil {
		t.Fatal(err)
	}
	now := sigNow.Add(time.Second)
	if got, err := VerifyResponse(h, 200, body, "reqn", now, &key.PublicKey); err != nil || got.KeyID != "srv:01" {
		t.Fatalf("%+v %v", got, err)
	}
	clone := func() http.Header { return h.Clone() }
	bad := clone()
	bad.Set(HeaderSignatureInput, strings.Replace(h.Get(HeaderSignatureInput), `srv:01`, `srv:02`, 1))
	cases := map[string]func() error{
		"status":    func() error { _, e := VerifyResponse(h, 500, body, "reqn", now, &key.PublicKey); return e },
		"body":      func() error { _, e := VerifyResponse(h, 200, []byte("x"), "reqn", now, &key.PublicKey); return e },
		"req nonce": func() error { _, e := VerifyResponse(h, 200, body, "other", now, &key.PublicKey); return e },
		"wrong key": func() error { _, e := VerifyResponse(h, 200, body, "reqn", now, &sigKey(t).PublicKey); return e },
		"keyid":     func() error { _, e := VerifyResponse(bad, 200, body, "reqn", now, &key.PublicKey); return e },
		"skew": func() error {
			_, e := VerifyResponse(h, 200, body, "reqn", sigNow.Add(time.Hour), &key.PublicKey)
			return e
		},
		"unsigned": func() error { _, e := VerifyResponse(http.Header{}, 200, body, "reqn", now, &key.PublicKey); return e },
		"req as resp": func() error {
			r, _ := signedReq(t, key, body)
			_, e := VerifyResponse(r.Header, 200, body, "reqn", now, &key.PublicKey)
			return e
		},
	}
	for name, f := range cases {
		if f() == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
