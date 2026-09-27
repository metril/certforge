package importer

import (
	"context"
	"io/fs"
	"strings"
)

// AcmeSh parses an ~/.acme.sh state directory: one subdirectory per
// certificate, named <domain> (RSA) or <domain>_ecc (EC), holding either
// fullchain.cer (leaf followed by its chain, concatenated PEM) or
// <domain>.cer (leaf only) plus ca.cer (chain), and <domain>.key.
var AcmeSh Importer = acmeSh{}

type acmeSh struct{}

func (acmeSh) Detect(fsys fs.FS) bool {
	_, ok := acmeShRoot(fsys)
	return ok
}

func (acmeSh) Import(_ context.Context, fsys fs.FS) ([]ImportedCert, error) {
	root, ok := acmeShRoot(fsys)
	if !ok {
		return nil, nil
	}
	entries, err := fs.ReadDir(root, ".")
	if err != nil {
		return nil, err
	}
	var out []ImportedCert
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := e.Name()
		domain := strings.TrimSuffix(dir, "_ecc")
		leafDER, chainDER, ok := acmeShCertFiles(root, dir, domain)
		if !ok {
			continue
		}
		var key []byte
		if b, err := fs.ReadFile(root, dir+"/"+domain+".key"); err == nil {
			if der, ok := normalizeKeyPEM(b); ok {
				key = der
			} else {
				// A key file exists but could not be decoded: pass the raw
				// bytes through rather than silently reporting this
				// certificate as keyless. issuance.ImportCertificates
				// parses KeyPKCS8 itself and reports a "cannot parse key"
				// skip when that fails, so the caller learns a key file
				// was found and is unusable, not that none exists.
				key = b
			}
		}
		out = append(out, ImportedCert{Name: domain, Source: SourceAcmeSh, LeafDER: leafDER, ChainDER: chainDER, KeyPKCS8: key})
	}
	return out, nil
}

// acmeShCertFiles reads dir's certificate material: fullchain.cer when
// present (leaf is its first CERTIFICATE block, the chain is the rest), or
// <domain>.cer for the leaf plus ca.cer for the chain (ca.cer is optional;
// its absence is not itself a reason to drop the certificate). ok is false
// only when dir has neither file at all — not a certificate directory, so
// Import silently passes over it. When a recognized file is present but
// decodes to no CERTIFICATE block at all, ok is still true and leafDER is
// that file's own raw bytes: issuance.ImportCertificates' x509.
// ParseCertificate then fails on it with a real reason, and the caller
// sees a "cannot parse leaf" skip instead of this certificate silently
// vanishing from the results.
func acmeShCertFiles(fsys fs.FS, dir, domain string) (leafDER []byte, chainDER [][]byte, ok bool) {
	if b, err := fs.ReadFile(fsys, dir+"/fullchain.cer"); err == nil {
		if certs := decodeCertPEMs(b); len(certs) > 0 {
			return certs[0], certs[1:], true
		}
		return b, nil, true
	}
	b, err := fs.ReadFile(fsys, dir+"/"+domain+".cer")
	if err != nil {
		return nil, nil, false
	}
	certs := decodeCertPEMs(b)
	if len(certs) == 0 {
		return b, nil, true
	}
	if cb, err := fs.ReadFile(fsys, dir+"/ca.cer"); err == nil {
		chainDER = decodeCertPEMs(cb)
	}
	return certs[0], chainDER, true
}

// acmeShRoot returns the FS to search for certificate directories: fsys
// itself, or its .acme.sh subdirectory (an archive of a whole home
// directory, or of ~/.acme.sh's parent).
func acmeShRoot(fsys fs.FS) (fs.FS, bool) {
	if hasAcmeShLayout(fsys) {
		return fsys, true
	}
	if sub, err := fs.Sub(fsys, ".acme.sh"); err == nil && hasAcmeShLayout(sub) {
		return sub, true
	}
	return nil, false
}

// hasAcmeShLayout reports whether fsys has at least one top-level directory
// holding fullchain.cer or <name-without-_ecc>.cer, the two files every
// acme.sh certificate directory has one of.
func hasAcmeShLayout(fsys fs.FS) bool {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := fs.Stat(fsys, e.Name()+"/fullchain.cer"); err == nil {
			return true
		}
		domain := strings.TrimSuffix(e.Name(), "_ecc")
		if _, err := fs.Stat(fsys, e.Name()+"/"+domain+".cer"); err == nil {
			return true
		}
	}
	return false
}
