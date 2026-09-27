package render

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"unicode/utf8"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
)

const jksType = "application/x-java-keystore"

// JKS renders a single .jks file: a PrivateKeyEntry under Alias (leaf, key,
// chain) plus a TrustedCertificateEntry per extra certificate and per extra
// chain certificate (extra-<n>, extra-<n>-<m>). The password must be ASCII.
type JKS struct{}

// Format returns the renderer's format name.
func (JKS) Format() string { return "jks" }

// Render encodes m (and opts.Extras) into one password-protected .jks file.
// The store password equals the key password; both come from opts.Password.
func (JKS) Render(m Material, opts OutputOpts) ([]File, error) {
	if err := CheckJKSPassword(opts.Password); err != nil {
		return nil, err
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
		for j, c := range ex.ChainDER {
			if err := ks.SetTrustedCertificateEntry(fmt.Sprintf("extra-%d-%d", i+1, j+1), keystore.TrustedCertificateEntry{
				CreationTime: leaf.NotBefore,
				Certificate:  keystore.Certificate{Type: "X509", Content: c},
			}); err != nil {
				return nil, err
			}
		}
	}

	var buf bytes.Buffer
	if err := ks.Store(&buf, pw); err != nil {
		return nil, err
	}
	return []File{{Name: opts.BaseName + ".jks", ContentType: jksType, Data: buf.Bytes(), Secret: true}}, nil
}

// CheckJKSPassword enforces JKS's password constraints: at least 6 Unicode
// characters, and ASCII only. keystore-go's password hashing maps each
// UTF-8 byte of the password to one (0, byte) pair, as if it were the
// zero-extended high byte of a UTF-16 code unit; for a non-ASCII password
// (multi-byte UTF-8), that does not match the UTF-16 encoding Java's own
// KeyStore uses, so the resulting file cannot be opened with the same
// password in Java or keytool. Rejecting it here is safer than shipping a
// file that silently fails to open elsewhere.
//
// Exported so callers that store a password ahead of render time (a
// layout's password field) can apply the exact same rule before storing
// it, instead of a looser check that lets a password through storage only
// to have every later render of that layout's jks file fail.
func CheckJKSPassword(pw string) error {
	for i := 0; i < len(pw); i++ {
		if pw[i] >= utf8.RuneSelf {
			return fmt.Errorf("%w: JKS passwords must be ASCII", ErrPassword)
		}
	}
	if utf8.RuneCountInString(pw) < 6 {
		return ErrPassword
	}
	return nil
}
