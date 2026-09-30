// Package delivery is the shared, database-free model of what an agent
// installs: output layouts (files built from PEM parts), the Traefik
// file-provider target, hooks, and the sha256 digests drift compares. The
// server computes expected digests with it and certforge-agent writes files
// with it, so both always agree byte for byte.
package delivery

import (
	"fmt"
	"io/fs"
	"math"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/render"
)

// MaxLayoutFiles bounds a layout.
const MaxLayoutFiles = 20

// OutputFile is one file of a layout (stored as JSON in output_specs.files).
type OutputFile struct {
	Path     string   `json:"path"`
	Format   string   `json:"format"`
	Parts    []string `json:"parts"`
	Owner    string   `json:"owner"`
	Group    string   `json:"group"`
	Mode     string   `json:"mode"`
	Encoding string   `json:"encoding,omitempty"` // p12 only: modern (default) or legacy
	Alias    string   `json:"alias,omitempty"`    // jks only: default is the file's BaseName
}

// Layout is a whole output spec's rendering input: its files, the extra
// certificates it bundles alongside its own (rendered as the "extra" PEM
// part and as additional CA/trusted certificates in p12/jks), in write
// order, and the plaintext export password for any p12/jks file (empty
// when the layout has none).
type Layout struct {
	Files        []OutputFile
	ExtraCertIDs []uuid.UUID
	Password     string
}

// File is one rendered file ready to write.
type File struct {
	Path  string
	Owner string
	Group string
	Mode  string // four octal digits, for example 0640
	Data  []byte
}

// FieldError names the invalid field; the API returns it as a 422.
type FieldError struct{ Field, Msg string }

func (e *FieldError) Error() string { return e.Field + ": " + e.Msg }

var (
	modeRe  = regexp.MustCompile(`^0?[0-7]{3}$`)
	ownerRe = regexp.MustCompile(`^([a-z_][a-z0-9_.-]{0,31}|[0-9]{1,10})?$`)
	aliasRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
)

// CleanPath accepts only absolute, already-clean paths below / with no NUL.
func CleanPath(field, p string) error {
	if !strings.HasPrefix(p, "/") {
		return &FieldError{field, "must be an absolute path"}
	}
	if p == "/" || strings.ContainsRune(p, 0) || path.Clean(p) != p {
		return &FieldError{field, "must be a clean file path without . or .. segments or a trailing slash"}
	}
	return nil
}

var numericRe = regexp.MustCompile(`^[0-9]{1,10}$`)

// validateMode checks that s is an octal mode and refuses one that is
// world-writable: a layout file can hold a private key, and a mode an agent
// would write as world-writable is always a mistake.
func validateMode(field, s string) error {
	if !modeRe.MatchString(s) {
		return &FieldError{field, "mode must be octal, for example 0640"}
	}
	m, err := ParseMode(s)
	if err != nil {
		return &FieldError{field, "mode must be octal, for example 0640"}
	}
	if m&0o002 != 0 {
		return &FieldError{field, "mode must not be world-writable"}
	}
	return nil
}

// validateOwner checks that s is a user/group name or a numeric id that
// fits in a uint32 (the range chown accepts).
func validateOwner(field, s string) error {
	if !ownerRe.MatchString(s) {
		return &FieldError{field, "must be a user/group name or numeric id"}
	}
	if numericRe.MatchString(s) {
		v, err := strconv.ParseUint(s, 10, 64)
		if err != nil || v > math.MaxUint32 {
			return &FieldError{field, "numeric id must fit in 32 bits"}
		}
	}
	return nil
}

// ValidateFiles checks a layout's files.
func ValidateFiles(files []OutputFile) error {
	if len(files) == 0 || len(files) > MaxLayoutFiles {
		return &FieldError{"files", fmt.Sprintf("a layout has 1 to %d files", MaxLayoutFiles)}
	}
	seen := map[string]bool{}
	for i, f := range files {
		field := fmt.Sprintf("files[%d]", i)
		if err := CleanPath(field+".path", f.Path); err != nil {
			return err
		}
		if seen[f.Path] {
			return &FieldError{field + ".path", "each path may appear once"}
		}
		seen[f.Path] = true
		if !slices.Contains(render.Formats, f.Format) {
			return &FieldError{field + ".format", fmt.Sprintf("unknown format %q", f.Format)}
		}
		switch f.Format {
		case "pem":
			if len(f.Parts) == 0 {
				return &FieldError{field + ".parts", "choose at least one part"}
			}
		case "der":
			if len(f.Parts) != 1 || (f.Parts[0] != "cert" && f.Parts[0] != "key") {
				return &FieldError{field + ".parts", "a der file holds exactly one part, cert or key; chain is download-only"}
			}
		case "p12", "jks":
			if len(f.Parts) != 0 {
				return &FieldError{field + ".parts", "p12 and jks files take no parts"}
			}
		}
		for _, p := range f.Parts {
			if !slices.Contains(render.Parts, p) {
				return &FieldError{field + ".parts", fmt.Sprintf("unknown part %q", p)}
			}
		}
		if f.Encoding != "" {
			if f.Format != "p12" {
				return &FieldError{field + ".encoding", "encoding is only valid for p12 files"}
			}
			if f.Encoding != "modern" && f.Encoding != "legacy" {
				return &FieldError{field + ".encoding", "encoding must be modern or legacy"}
			}
		}
		if f.Alias != "" {
			if f.Format != "jks" {
				return &FieldError{field + ".alias", "alias is only valid for jks files"}
			}
			if !aliasRe.MatchString(f.Alias) {
				return &FieldError{field + ".alias", `alias must match ^[A-Za-z0-9._-]{1,64}$`}
			}
		}
		if err := validateMode(field+".mode", f.Mode); err != nil {
			return err
		}
		if err := validateOwner(field+".owner", f.Owner); err != nil {
			return err
		}
		if err := validateOwner(field+".group", f.Group); err != nil {
			return err
		}
	}
	return nil
}

// ParseMode parses an octal mode string.
func ParseMode(s string) (fs.FileMode, error) {
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil {
		return 0, fmt.Errorf("delivery: mode %q: %w", s, err)
	}
	return fs.FileMode(v) & fs.ModePerm, nil
}

func normMode(s string) string {
	if len(s) == 3 {
		return "0" + s
	}
	return s
}

// baseName returns a path's file name without its extension, for
// OutputOpts.BaseName in DER/PKCS12/JKS output ("/etc/x/site.p12" -> "site").
func baseName(p string) string {
	b := path.Base(p)
	if i := strings.LastIndex(b, "."); i > 0 {
		b = b[:i]
	}
	return b
}

// RenderLayout renders every file of l against m (the layout's own
// certificate material) and extras (the layout's extra certificates, keyed
// by certificate id; only the ids named by l.ExtraCertIDs are used, in that
// order, matching render.OutputOpts.Extras). Each file's randomness for
// PKCS12/JKS is render.DetRand(m.PrivateKeyPKCS8, l.Password, f.Path): the
// same material, password and path always render the same bytes, and a
// changed password changes them, per the ledger ruling that keystore
// randomness must never be seeded from public ids alone.
func RenderLayout(m render.Material, extras map[uuid.UUID]render.Material, l Layout) ([]File, error) {
	extraList := make([]render.Material, 0, len(l.ExtraCertIDs))
	for _, id := range l.ExtraCertIDs {
		ex, ok := extras[id]
		if !ok {
			return nil, fmt.Errorf("delivery: no material for extra certificate %s", id)
		}
		extraList = append(extraList, ex)
	}
	out := make([]File, 0, len(l.Files))
	for _, f := range l.Files {
		r, ok := render.For(f.Format)
		if !ok {
			return nil, fmt.Errorf("delivery: unknown format %q", f.Format)
		}
		opts := render.OutputOpts{
			Parts:    f.Parts,
			Password: l.Password,
			Encoding: f.Encoding,
			Alias:    f.Alias,
			BaseName: baseName(f.Path),
			Extras:   extraList,
			Rand:     render.DetRand(m.PrivateKeyPKCS8, []byte(l.Password), []byte(f.Path)),
		}
		rendered, err := r.Render(m, opts)
		if err != nil {
			return nil, err
		}
		var data []byte
		for _, rf := range rendered {
			data = append(data, rf.Data...)
		}
		out = append(out, File{Path: f.Path, Owner: f.Owner, Group: f.Group, Mode: normMode(f.Mode), Data: data})
	}
	return out, nil
}

// NeedsKey reports whether any file renders key material: PEM key/combined,
// DER key, or any p12/jks file (which always includes the key).
func NeedsKey(files []OutputFile) bool {
	for _, f := range files {
		switch f.Format {
		case "p12", "jks":
			return true
		case "pem", "der":
			if slices.Contains(f.Parts, "key") || slices.Contains(f.Parts, "combined") {
				return true
			}
		}
	}
	return false
}

// TargetMaterial renders the fullchain and key PEM an agent-side target uses.
func TargetMaterial(m render.Material) (agentproto.Material, error) {
	pem, err := render.PEM{}.Render(m, render.OutputOpts{Parts: []string{"fullchain", "key"}})
	if err != nil {
		return agentproto.Material{}, err
	}
	return agentproto.Material{Fullchain: pem[0].Data, Key: pem[1].Data}, nil
}

// GrantFiles renders a grant's layout files, in write order. l is nil when
// the grant has no layout, and a layout never renders without material: m
// nil (a certificate with no version yet, C3) or an empty l returns nil,
// nil. A grant's target files (Traefik's, which do render with m nil — its
// ACME router file — a version-less grant's only renderable file at all)
// are targets.GrantFiles' own job, layered on top of this.
func GrantFiles(m *render.Material, extras map[uuid.UUID]render.Material, l *Layout) ([]File, error) {
	if m == nil || l == nil || len(l.Files) == 0 {
		return nil, nil
	}
	return RenderLayout(*m, extras, *l)
}
