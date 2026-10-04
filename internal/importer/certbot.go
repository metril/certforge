package importer

import (
	"context"
	"io/fs"
	"regexp"
	"sort"
	"strconv"
)

// Certbot parses an /etc/letsencrypt state directory: for each name,
// archive/<name>/{cert,chain,fullchain,privkey}N.pem at the highest N;
// when archive/<name> has none of those, live/<name>/{cert,chain,
// fullchain,privkey}.pem (regular files: certbot normally symlinks these
// into archive/, but ExtractArchive already drops symlinks, so what
// remains under live/ after extraction is only ever a real copy).
var Certbot Importer = certbot{}

type certbot struct{}

func (certbot) Detect(fsys fs.FS) bool {
	_, ok := certbotRoot(fsys)
	return ok
}

func (certbot) Import(_ context.Context, fsys fs.FS) ([]ImportedCert, error) {
	root, ok := certbotRoot(fsys)
	if !ok {
		return nil, nil
	}
	var out []ImportedCert
	for _, name := range certbotNames(root) {
		if ic, ok := certbotImportOne(root, name); ok {
			out = append(out, ic)
		}
	}
	return out, nil
}

// certbotRoot returns the FS to search: the shallowest directory within a
// few levels of fsys that has certbot's archive/ or live/ layout (an archive
// of /etc, or of a whole filesystem, rather than of /etc/letsencrypt itself).
func certbotRoot(fsys fs.FS) (fs.FS, bool) {
	return findRoot(fsys, hasCertbotLayout)
}

func hasCertbotLayout(fsys fs.FS) bool {
	for _, d := range [...]string{"archive", "live"} {
		entries, err := fs.ReadDir(fsys, d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() {
				return true
			}
		}
	}
	return false
}

// certbotNames returns every name found under archive/ or live/, sorted
// and de-duplicated (a name can appear under both).
func certbotNames(fsys fs.FS) []string {
	seen := map[string]bool{}
	var names []string
	for _, d := range [...]string{"archive", "live"} {
		entries, err := fs.ReadDir(fsys, d)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() && !seen[e.Name()] {
				seen[e.Name()] = true
				names = append(names, e.Name())
			}
		}
	}
	sort.Strings(names)
	return names
}

var certbotArchiveFileRe = regexp.MustCompile(`^(?:cert|chain|fullchain|privkey)(\d+)\.pem$`)

func certbotImportOne(fsys fs.FS, name string) (ImportedCert, bool) {
	if ic, ok := certbotFromArchive(fsys, name); ok {
		return ic, true
	}
	return certbotFromLive(fsys, name)
}

// certbotFromArchive picks the highest-numbered generation under
// archive/<name> (certbot renews by writing cert2.pem, chain2.pem, and so
// on, alongside the originals; the highest N is the live one) and reads
// its four files by that same suffix.
func certbotFromArchive(fsys fs.FS, name string) (ImportedCert, bool) {
	dir := "archive/" + name
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return ImportedCert{}, false
	}
	best := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		m := certbotArchiveFileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		if n, err := strconv.Atoi(m[1]); err == nil && n > best {
			best = n
		}
	}
	if best == 0 {
		return ImportedCert{}, false
	}
	suffix := strconv.Itoa(best)
	return certbotAssemble(fsys, name, dir+"/cert"+suffix+".pem", dir+"/chain"+suffix+".pem",
		dir+"/fullchain"+suffix+".pem", dir+"/privkey"+suffix+".pem")
}

func certbotFromLive(fsys fs.FS, name string) (ImportedCert, bool) {
	dir := "live/" + name
	return certbotAssemble(fsys, name, dir+"/cert.pem", dir+"/chain.pem", dir+"/fullchain.pem", dir+"/privkey.pem")
}

// certbotAssemble reads a certificate's four well-known files: fullchain
// gives the leaf plus its chain when readable; cert alone supplies the leaf
// otherwise (chain alone, if present, still supplies the chain). ok is
// false only when none of fullchain/cert exists at all — nothing here to
// import. When one of them is readable but decodes to no CERTIFICATE block
// at all, ok is still true and leafDER is that file's own raw bytes (the
// same "surface it, don't vanish it" contract acmeShCertFiles follows): the
// caller's x509.ParseCertificate then reports why, as a "cannot parse
// leaf" skip. A key is optional; one that exists but cannot be decoded is
// passed through the same way, so the caller reports "cannot parse key"
// instead of silently treating this certificate as keyless.
func certbotAssemble(fsys fs.FS, name, certPath, chainPath, fullchainPath, keyPath string) (ImportedCert, bool) {
	var leafDER []byte
	var chainDER [][]byte
	var found bool
	var undecodable []byte
	if b, err := fs.ReadFile(fsys, fullchainPath); err == nil {
		found = true
		if certs := decodeCertPEMs(b); len(certs) > 0 {
			leafDER, chainDER = certs[0], certs[1:]
		} else {
			undecodable = b
		}
	}
	if leafDER == nil {
		if b, err := fs.ReadFile(fsys, certPath); err == nil {
			found = true
			if certs := decodeCertPEMs(b); len(certs) > 0 {
				leafDER = certs[0]
			} else if undecodable == nil {
				undecodable = b
			}
		}
	}
	if leafDER == nil {
		if !found {
			return ImportedCert{}, false
		}
		leafDER = undecodable
	}
	if chainDER == nil {
		if b, err := fs.ReadFile(fsys, chainPath); err == nil {
			chainDER = decodeCertPEMs(b)
		}
	}
	var key []byte
	if b, err := fs.ReadFile(fsys, keyPath); err == nil {
		if der, ok := normalizeKeyPEM(b); ok {
			key = der
		} else {
			key = b
		}
	}
	return ImportedCert{Name: name, Source: SourceCertbot, LeafDER: leafDER, ChainDER: chainDER, KeyPKCS8: key}, true
}
