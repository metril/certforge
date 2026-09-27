package render

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"fmt"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

const jksType = "application/x-java-keystore"

// JKS renders a single .jks file: a PrivateKeyEntry under Alias (leaf, key,
// chain) plus a TrustedCertificateEntry per extra certificate.
type JKS struct{}

// Format returns the renderer's format name.
func (JKS) Format() string { return "jks" }

// Render encodes m (and opts.Extras) into one password-protected .jks file.
// The store password equals the key password; both come from opts.Password.
func (JKS) Render(m Material, opts OutputOpts) ([]File, error) {
	if len(opts.Password) < 6 {
		return nil, ErrPassword
	}
	if len(m.PrivateKeyPKCS8) == 0 {
		return nil, ErrNoKey
	}
	leaf, err := x509.ParseCertificate(m.LeafDER)
	if err != nil {
		return nil, fmt.Errorf("parse leaf: %w", err)
	}

	alias := opts.Alias
	if alias == "" {
		alias = opts.BaseName
	}

	r := opts.Rand
	if r == nil {
		r = rand.Reader
	}
	ks := keystore.New(keystore.WithOrderedAliases(), keystore.WithCustomRandomNumberGenerator(r))

	chain := []keystore.Certificate{{Type: "X509", Content: m.LeafDER}}
	for _, c := range m.ChainDER {
		chain = append(chain, keystore.Certificate{Type: "X509", Content: c})
	}
	pw := []byte(opts.Password)
	if err := ks.SetPrivateKeyEntry(alias, keystore.PrivateKeyEntry{
		CreationTime:     leaf.NotBefore,
		PrivateKey:       m.PrivateKeyPKCS8,
		CertificateChain: chain,
	}, pw); err != nil {
		return nil, err
	}

	for i, ex := range opts.Extras {
		if err := ks.SetTrustedCertificateEntry(fmt.Sprintf("extra-%d", i+1), keystore.TrustedCertificateEntry{
			CreationTime: leaf.NotBefore,
			Certificate:  keystore.Certificate{Type: "X509", Content: ex.LeafDER},
		}); err != nil {
			return nil, err
		}
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, pw); err != nil {
		return nil, err
	}
	return []File{{Name: opts.BaseName + ".jks", ContentType: jksType, Data: buf.Bytes(), Secret: true}}, nil
}
