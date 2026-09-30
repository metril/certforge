package targets

import (
	"context"
	"encoding/json"

	"github.com/metril/certforge/internal/delivery"
)

// Traefik is the "traefik" file-provider deploy target type: it always
// runs on the agent and always needs the certificate's private key (a
// Traefik TLS certificate always needs both a certFile and a keyFile).
type Traefik struct{}

// Type implements Target.
func (Traefik) Type() string { return "traefik" }

// Name implements Target.
func (Traefik) Name() string { return "Traefik" }

// Schema implements Target: delivery.TraefikSchema, unchanged.
func (Traefik) Schema() json.RawMessage { return json.RawMessage(delivery.TraefikSchema) }

// RunsOn implements Target: always Agent.
func (Traefik) RunsOn() Mode { return Agent }

// KeyPolicy implements Target: always needs the key.
func (Traefik) KeyPolicy() KeyPolicy { return Always }

// Parse implements Target: delivery.ParseTraefik, with Public the
// canonicalized TraefikConfig and no secret fields.
func (Traefik) Parse(raw json.RawMessage) (Config, error) {
	cfg, err := delivery.ParseTraefik(raw)
	if err != nil {
		return Config{}, err
	}
	pub, err := json.Marshal(cfg)
	if err != nil {
		return Config{}, err
	}
	return Config{Public: pub, Secrets: map[string]string{}, NeedsKey: true}, nil
}

// Deploy implements Target: a file target's Deploy returns Result{Files}
// with no side effects (Deviations R2) — the files are written by the
// agent, not here.
func (t Traefik) Deploy(_ context.Context, req Request) (Result, error) {
	files, err := t.Files(req)
	if err != nil {
		return Result{}, err
	}
	return Result{Files: files}, nil
}

// Files implements FileTarget: req.Material == nil (a version-less grant,
// C3) renders only the ACME router file when acmeServiceUrl is set (or no
// files at all); otherwise it renders the full RenderTraefik set from the
// material's own fullchain and key PEM (delivery.TargetMaterial).
func (Traefik) Files(req Request) ([]delivery.File, error) {
	var cfg delivery.TraefikConfig
	if err := json.Unmarshal(req.Config, &cfg); err != nil {
		return nil, err
	}
	if req.Material == nil {
		if f := delivery.AcmeRouterFile(req.CertName, req.Names, cfg); f != nil {
			return []delivery.File{*f}, nil
		}
		return nil, nil
	}
	mat, err := delivery.TargetMaterial(*req.Material)
	if err != nil {
		return nil, err
	}
	return delivery.RenderTraefik(req.CertName, req.Names, cfg, mat.Fullchain, mat.Key), nil
}

// Paths implements FileTarget: the paths RenderTraefik would write for cfg
// and certName, with no material and no names needed (only .Path is read).
func (Traefik) Paths(cfg json.RawMessage, certName string) ([]string, error) {
	var c delivery.TraefikConfig
	if err := json.Unmarshal(cfg, &c); err != nil {
		return nil, err
	}
	files := delivery.RenderTraefik(certName, nil, c, nil, nil)
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = f.Path
	}
	return out, nil
}
