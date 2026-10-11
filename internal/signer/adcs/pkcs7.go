package adcs

import (
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
)

var oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}

type contentInfo struct {
	Type    asn1.ObjectIdentifier
	Content asn1.RawValue // the [0] EXPLICIT wrapper; its Bytes are the SignedData
}

type signedData struct {
	Version int
	Digests asn1.RawValue
	Encap   asn1.RawValue
	Certs   asn1.RawValue `asn1:"optional,tag:0"`
	CRLs    asn1.RawValue `asn1:"optional,tag:1"`
	Signers asn1.RawValue
}

// parseCertsOnlyPKCS7 extracts the certificates from a certs-only CMS
// SignedData (the "degenerate" PKCS#7 AD CS returns). Signatures are not
// checked; DER encoding is assumed.
func parseCertsOnlyPKCS7(der []byte) ([]*x509.Certificate, error) {
	var ci contentInfo
	if _, err := asn1.Unmarshal(der, &ci); err != nil {
		return nil, fmt.Errorf("pkcs7: content info: %w", err)
	}
	if !ci.Type.Equal(oidSignedData) {
		return nil, fmt.Errorf("pkcs7: unexpected content type %v", ci.Type)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("pkcs7: signed data: %w", err)
	}
	if len(sd.Certs.Bytes) == 0 {
		return nil, errors.New("pkcs7: no certificates")
	}
	var out []*x509.Certificate
	rest := sd.Certs.Bytes
	for len(rest) > 0 {
		var rv asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &rv); err != nil {
			return nil, fmt.Errorf("pkcs7: certificate set: %w", err)
		}
		c, err := x509.ParseCertificate(rv.FullBytes)
		if err != nil {
			return nil, fmt.Errorf("pkcs7: parse certificate: %w", err)
		}
		out = append(out, c)
	}
	return out, nil
}
