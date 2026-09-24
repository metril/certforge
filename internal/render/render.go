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
}

// OutputOpts selects what to render.
type OutputOpts struct {
	Parts []string // cert, chain, fullchain, key, combined
}

// Renderer is implemented per output format.
type Renderer interface {
	Format() string
	Render(m Material, opts OutputOpts) ([]File, error)
}

// ErrNoKey is returned when "key" or "combined" is requested without a key.
var ErrNoKey = errors.New("private key not available")

// Parts lists the valid PEM parts in canonical order.
var Parts = []string{"cert", "chain", "fullchain", "key", "combined"}

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
		default:
			return nil, fmt.Errorf("unknown part %q", p)
		}
		out = append(out, File{Name: fileName(p), ContentType: pemType, Data: data})
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
		if f.Name == "privkey.pem" || f.Name == "combined.pem" {
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
