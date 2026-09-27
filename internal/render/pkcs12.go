package render

import (
	"crypto/x509"
	"fmt"

	"software.sslmate.com/src/go-pkcs12"
)

const p12Type = "application/x-pkcs12"

// PKCS12 renders a single .p12 file holding the leaf, its chain, any extra
// certificates (as CA certificates), and the private key.
type PKCS12 struct{}

// Format returns the renderer's format name.
func (PKCS12) Format() string { return "p12" }

// Render encodes m (and opts.Extras) into one password-protected .p12 file.
func (PKCS12) Render(m Material, opts OutputOpts) ([]File, error) {
	if opts.Password == "" {
		return nil, ErrPassword
	}
	if len(m.PrivateKeyPKCS8) == 0 {
		return nil, ErrNoKey
	}
	leaf, err := x509.ParseCertificate(m.LeafDER)
	if err != nil {
		return nil, fmt.Errorf("parse leaf: %w", err)
	}
	key, err := x509.ParsePKCS8PrivateKey(m.PrivateKeyPKCS8)
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	caCerts, err := caCertsFor(m, opts.Extras)
	if err != nil {
		return nil, err
	}

	var enc *pkcs12.Encoder
	switch opts.Encoding {
	case "", "modern":
		enc = pkcs12.Modern2023
	case "legacy":
		enc = pkcs12.Legacy
	default:
		return nil, fmt.Errorf("unknown pkcs12 encoding %q", opts.Encoding)
	}
	if opts.Rand != nil {
		enc = enc.WithRand(opts.Rand)
	}
	data, err := enc.Encode(key, leaf, caCerts, opts.Password)
	if err != nil {
		return nil, err
	}
	return []File{{Name: opts.BaseName + ".p12", ContentType: p12Type, Data: data, Secret: true}}, nil
}

// caCertsFor parses m's chain followed by each extra's leaf and chain, in
// order, for use as PKCS12/JKS CA/trusted certificates.
func caCertsFor(m Material, extras []Material) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	for _, c := range m.ChainDER {
		cert, err := x509.ParseCertificate(c)
		if err != nil {
			return nil, fmt.Errorf("parse chain cert: %w", err)
		}
		out = append(out, cert)
	}
	for _, ex := range extras {
		leaf, err := x509.ParseCertificate(ex.LeafDER)
		if err != nil {
			return nil, fmt.Errorf("parse extra leaf: %w", err)
		}
		out = append(out, leaf)
		for _, c := range ex.ChainDER {
			cert, err := x509.ParseCertificate(c)
			if err != nil {
				return nil, fmt.Errorf("parse extra chain cert: %w", err)
			}
			out = append(out, cert)
		}
	}
	return out, nil
}
