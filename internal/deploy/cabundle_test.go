package deploy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/sshx/sshxtest"
)

func TestCAPemValidatedAndNormalized(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &k.PublicKey, k)
	good := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	base := map[string]map[string]any{
		"pfsense":   {"url": "https://h.example/api", "username": "a", "password": "p"},
		"truenas":   {"url": "https://h.example", "apiKey": "k"},
		"routeros":  {"url": "https://h.example", "username": "a", "password": "p", "hostKey": sshxtest.Start(t, nil).HostLine()},
		"authentik": {"url": "https://h.example", "token": "t"},
	}
	impls := map[string]targets.Target{"pfsense": PfSense{}, "truenas": TrueNAS{}, "routeros": RouterOS{}, "authentik": Authentik{}}
	for name, tg := range impls {
		parse := func(ca string) (targets.Config, error) {
			m := map[string]any{"caPem": ca}
			for k, v := range base[name] {
				m[k] = v
			}
			raw, _ := json.Marshal(m)
			return tg.Parse(raw)
		}
		if _, err := parse("not a pem"); err == nil {
			t.Errorf("%s: accepted junk", name)
		} else {
			var fe *delivery.FieldError
			if !errors.As(err, &fe) || fe.Field != "config.caPem" {
				t.Errorf("%s: err = %v", name, err)
			}
		}
		cfg, err := parse(strings.ReplaceAll(good, "\n", "\r\n"))
		if err != nil {
			t.Errorf("%s: rejected good bundle: %v", name, err)
			continue
		}
		if strings.Contains(string(cfg.Public), "\\r") {
			t.Errorf("%s: CRLF kept", name)
		}
	}
}
