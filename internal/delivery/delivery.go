// Package delivery is the shared, database-free model of what an agent
// installs: output layouts (files built from PEM parts), the Traefik
// file-provider target, hooks, and the sha256 digests drift compares. The
// server computes expected digests with it and certforge-agent writes files
// with it, so both always agree byte for byte.
package delivery

import (
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/render"
)

// MaxLayoutFiles bounds a layout.
const MaxLayoutFiles = 20

// OutputFile is one file of a layout (stored as JSON in output_specs.files).
type OutputFile struct {
	Path   string   `json:"path"`
	Format string   `json:"format"`
	Parts  []string `json:"parts"`
	Owner  string   `json:"owner"`
	Group  string   `json:"group"`
	Mode   string   `json:"mode"`
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
		if f.Format != "pem" {
			return &FieldError{field + ".format", "format must be pem"}
		}
		if len(f.Parts) == 0 {
			return &FieldError{field + ".parts", "choose at least one part"}
		}
		for _, p := range f.Parts {
			if !slices.Contains(render.Parts, p) {
				return &FieldError{field + ".parts", fmt.Sprintf("unknown part %q", p)}
			}
		}
		if !modeRe.MatchString(f.Mode) {
			return &FieldError{field + ".mode", "mode must be octal, for example 0640"}
		}
		if !ownerRe.MatchString(f.Owner) {
			return &FieldError{field + ".owner", "owner must be a user name or numeric uid"}
		}
		if !ownerRe.MatchString(f.Group) {
			return &FieldError{field + ".group", "group must be a group name or numeric gid"}
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

// RenderLayout renders each file by concatenating its PEM parts in order.
func RenderLayout(m render.Material, files []OutputFile) ([]File, error) {
	out := make([]File, 0, len(files))
	for _, f := range files {
		parts, err := render.PEM{}.Render(m, render.OutputOpts{Parts: f.Parts})
		if err != nil {
			return nil, err
		}
		var data []byte
		for _, p := range parts {
			data = append(data, p.Data...)
		}
		out = append(out, File{Path: f.Path, Owner: f.Owner, Group: f.Group, Mode: normMode(f.Mode), Data: data})
	}
	return out, nil
}

// TargetMaterial renders the fullchain and key PEM an agent-side target uses.
func TargetMaterial(m render.Material) (agentproto.Material, error) {
	pem, err := render.PEM{}.Render(m, render.OutputOpts{Parts: []string{"fullchain", "key"}})
	if err != nil {
		return agentproto.Material{}, err
	}
	return agentproto.Material{Fullchain: pem[0].Data, Key: pem[1].Data}, nil
}

// GrantFiles renders everything a grant installs, in write order: the
// layout's files, then the target's.
func GrantFiles(m render.Material, layout []OutputFile, target *agentproto.Target, certName string) ([]File, error) {
	var out []File
	if len(layout) > 0 {
		lf, err := RenderLayout(m, layout)
		if err != nil {
			return nil, err
		}
		out = append(out, lf...)
	}
	if target != nil {
		cfg, err := ParseTarget(target.Type, target.Config)
		if err != nil {
			return nil, err
		}
		mat, err := TargetMaterial(m)
		if err != nil {
			return nil, err
		}
		out = append(out, RenderTraefik(certName, cfg, mat.Fullchain, mat.Key)...)
	}
	return out, nil
}
