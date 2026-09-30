package targetstest

import (
	"context"
	"encoding/json"
	"fmt"
	"path"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/targets"
)

// File is a test agent-side FileTarget (RunsOn Agent, KeyPolicy Always): its
// Files writes <dir>/<delivery.SafeName(cert)>.pem, the fullchain only, and
// it implements targets.Reloader, counting Reload calls.
type File struct {
	Code      string
	Reloads   int
	ReloadErr error
}

// Type implements targets.Target.
func (f *File) Type() string { return f.Code }

// Name implements targets.Target.
func (f *File) Name() string { return f.Code }

// Schema implements targets.Target: dir (required, no secrets).
func (f *File) Schema() json.RawMessage {
	return json.RawMessage(`{
  "type": "object",
  "additionalProperties": false,
  "required": ["dir"],
  "properties": {
    "dir": {"type": "string", "description": "Directory the agent writes the certificate file into."}
  }
}`)
}

// RunsOn implements targets.Target: always Agent.
func (f *File) RunsOn() targets.Mode { return targets.Agent }

// KeyPolicy implements targets.Target: always needs the key.
func (f *File) KeyPolicy() targets.KeyPolicy { return targets.Always }

// Parse implements targets.Target.
func (f *File) Parse(raw json.RawMessage) (targets.Config, error) {
	var doc struct {
		Dir string `json:"dir"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return targets.Config{}, fmt.Errorf("targetstest: %w", err)
	}
	if doc.Dir == "" {
		return targets.Config{}, fmt.Errorf("targetstest: dir: required")
	}
	return targets.Config{Public: raw, Secrets: map[string]string{}, NeedsKey: true}, nil
}

// Deploy implements targets.Target: a file target's Deploy returns
// Result{Files} with no side effects (Deviations R2) — the files are
// written by the agent, not here.
func (f *File) Deploy(_ context.Context, req targets.Request) (targets.Result, error) {
	files, err := f.Files(req)
	if err != nil {
		return targets.Result{}, err
	}
	return targets.Result{Files: files}, nil
}

// Files implements targets.FileTarget: the fullchain PEM at
// <dir>/<SafeName(cert)>.pem. nil, nil for a version-less grant (no
// Material), matching every other FileTarget.
func (f *File) Files(req targets.Request) ([]delivery.File, error) {
	if req.Material == nil {
		return nil, nil
	}
	var cfg struct {
		Dir string `json:"dir"`
	}
	if err := json.Unmarshal(req.Config, &cfg); err != nil {
		return nil, fmt.Errorf("targetstest: %w", err)
	}
	rendered, err := render.PEM{}.Render(*req.Material, render.OutputOpts{Parts: []string{"fullchain"}})
	if err != nil {
		return nil, err
	}
	return []delivery.File{{
		Path: path.Join(cfg.Dir, delivery.SafeName(req.CertName)+".pem"),
		Mode: "0644",
		Data: rendered[0].Data,
	}}, nil
}

// Paths implements targets.FileTarget.
func (f *File) Paths(cfg json.RawMessage, certName string) ([]string, error) {
	var c struct {
		Dir string `json:"dir"`
	}
	if err := json.Unmarshal(cfg, &c); err != nil {
		return nil, fmt.Errorf("targetstest: %w", err)
	}
	return []string{path.Join(c.Dir, delivery.SafeName(certName)+".pem")}, nil
}

// Reload implements targets.Reloader.
func (f *File) Reload(_ context.Context, _ targets.Request) (string, error) {
	f.Reloads++
	if f.ReloadErr != nil {
		return "", f.ReloadErr
	}
	return "reloaded", nil
}
