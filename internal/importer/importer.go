// Package importer detects and parses acme.sh and certbot certificate
// trees (as produced by ExtractArchive, or any other fs.FS) into
// normalized ImportedCert values. It knows nothing about CertForge's own
// data model: internal/issuance's ImportCertificates turns each
// ImportedCert into a stored certificate.
package importer

import (
	"context"
	"io/fs"
)

// Source names which tool's on-disk layout an ImportedCert was found in.
type Source string

const (
	SourceAcmeSh  Source = "acmesh"
	SourceCertbot Source = "certbot"
)

// ImportedCert is one certificate an Importer found: a leaf, its chain (in
// whatever order the tool stored it, leaf itself excluded), and an
// optional key, all still DER/PKCS8. Callers parse the leaf, derive names,
// validity and chain order, and decide whether and how to store it.
type ImportedCert struct {
	Name     string   // the certificate's name, derived from the archive (a directory name)
	Source   Source   // which importer found it
	LeafDER  []byte   // the leaf certificate, DER
	ChainDER [][]byte // the certificates found alongside the leaf, DER, order not guaranteed
	KeyPKCS8 []byte   // nil when no key was found
}

// Importer detects and parses one on-disk certificate-tool layout.
type Importer interface {
	// Detect reports whether fsys' root, or the single top-level directory
	// this layout is normally rooted at (".acme.sh", "letsencrypt"), looks
	// like this tool's tree.
	Detect(fsys fs.FS) bool
	// Import parses every certificate this layout can find under fsys. A
	// name whose certificate files are missing or cannot be decoded at all
	// is left out of the result rather than failing the whole call; only
	// an I/O-level failure reading the tree itself is returned as an
	// error.
	Import(ctx context.Context, fsys fs.FS) ([]ImportedCert, error)
}
