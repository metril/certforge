// Package render turns canonical certificate material (leaf DER, chain DER,
// PKCS#8 key) into files. Phase 1 ships PEM; DER, PKCS#12 and JKS renderers
// implement the same Renderer interface in Phase 4.
package render

import (
	"archive/zip"
	"bytes"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"time"
)

// Material is canonical certificate material.
type Material struct {
	LeafDER         []byte
	ChainDER        [][]byte
	PrivateKeyPKCS8 []byte // nil unless the caller may export keys
}

// File is one rendered output.
type File struct {
	Name        string
	ContentType string
	Data        []byte
	Secret      bool // true for key-bearing files: 0600 in Zip, in place of name matching
}

// OutputOpts selects what to render and, for DER/PKCS12/JKS, how.
type OutputOpts struct {
	Parts    []string // cert, chain, fullchain, key, combined, extra (PEM); cert, chain, key (DER)
	Password string   // PKCS12, JKS
	Encoding string   // PKCS12: modern (default), legacy
	Alias    string   // JKS entry alias; default BaseName
	BaseName string   // DER/PKCS12/JKS file base name (without extension)
	Extras   []Material
	Rand     io.Reader // nil uses crypto/rand
}

// Renderer is implemented per output format.
type Renderer interface {
	Format() string
	Render(m Material, opts OutputOpts) ([]File, error)
}

// ErrNoKey is returned when a key-bearing part or format is requested
// without a stored private key: PEM "key"/"combined", DER "key", or any
// PKCS12/JKS render.
var ErrNoKey = errors.New("private key not available")

// ErrNotDER is returned when a PEM-only part (fullchain, combined) is
// requested from the DER renderer.
var ErrNotDER = errors.New("not available as DER")

// ErrPassword is returned for an empty PKCS12 password or a JKS password
// shorter than 6 characters.
var ErrPassword = errors.New("invalid export password")

// Parts lists the valid PEM parts in canonical order.
var Parts = []string{"cert", "chain", "fullchain", "key", "combined", "extra"}

// Formats lists the valid output formats.
var Formats = []string{"pem", "der", "p12", "jks"}

// For returns the Renderer for format, or false if format is unknown.
func For(format string) (Renderer, bool) {
	switch format {
	case "pem":
		return PEM{}, true
	case "der":
		return DER{}, true
	case "p12":
		return PKCS12{}, true
	case "jks":
		return JKS{}, true
	}
	return nil, false
}

const pemType = "application/x-pem-file"

// PEM renders PEM parts.
type PEM struct{}

// Format returns the renderer's format name.
func (PEM) Format() string { return "pem" }

// Render renders the requested parts as PEM files.
func (PEM) Render(m Material, opts OutputOpts) ([]File, error) {
	if len(opts.Parts) == 0 {
		return nil, errors.New("no parts requested")
	}
	seen := map[string]bool{}
	var out []File
	for _, p := range opts.Parts {
		if seen[p] {
			continue
		}
		seen[p] = true
		var data []byte
		switch p {
		case "cert":
			data = certPEM(m.LeafDER)
		case "chain":
			data = chainPEM(m.ChainDER)
		case "fullchain":
			data = append(certPEM(m.LeafDER), chainPEM(m.ChainDER)...)
		case "key":
			if len(m.PrivateKeyPKCS8) == 0 {
				return nil, ErrNoKey
			}
			data = keyPEM(m.PrivateKeyPKCS8)
		case "combined":
			if len(m.PrivateKeyPKCS8) == 0 {
				return nil, ErrNoKey
			}
			data = append(append(certPEM(m.LeafDER), chainPEM(m.ChainDER)...), keyPEM(m.PrivateKeyPKCS8)...)
		case "extra":
			for _, ex := range opts.Extras {
				data = append(data, certPEM(ex.LeafDER)...)
				data = append(data, chainPEM(ex.ChainDER)...)
			}
		default:
			return nil, fmt.Errorf("unknown part %q", p)
		}
		out = append(out, File{Name: fileName(p), ContentType: pemType, Data: data, Secret: p == "key" || p == "combined"})
	}
	return out, nil
}

// Render renders PEM parts (Phase 1 entry point).
func Render(m Material, parts []string) ([]File, error) {
	return PEM{}.Render(m, OutputOpts{Parts: parts})
}

func fileName(part string) string {
	if part == "key" {
		return "privkey.pem"
	}
	return part + ".pem"
}

func certPEM(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func chainPEM(ders [][]byte) []byte {
	var b []byte
	for _, d := range ders {
		b = append(b, certPEM(d)...)
	}
	return b
}

func keyPEM(pkcs8 []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
}

// zipTime is fixed so identical inputs give byte-identical archives.
var zipTime = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

// Zip packs files into a deterministic zip archive.
func Zip(files []File) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range files {
		mode := fs.FileMode(0o644)
		if f.Secret {
			mode = 0o600
		}
		h := &zip.FileHeader{Name: f.Name, Method: zip.Deflate, Modified: zipTime}
		h.SetMode(mode)
		w, err := zw.CreateHeader(h)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.Data); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
