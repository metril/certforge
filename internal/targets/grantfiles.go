package targets

import (
	"fmt"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/render"
)

// GrantFiles renders everything a grant installs, in write order: the
// layout's own files (delivery.GrantFiles), then t's target files, when t
// names a registered FileTarget. t is nil for a grant with no target. m is
// nil for a certificate with no version yet (C3): delivery.GrantFiles
// already renders nothing from the layout then, and a FileTarget's own
// Files (Traefik's AcmeRouterFile) is the only thing that still renders
// with no material.
func GrantFiles(reg *Registry, m *render.Material, extras map[uuid.UUID]render.Material, l *delivery.Layout,
	t *agentproto.Target, certName string, names []string) ([]delivery.File, error) {
	out, err := delivery.GrantFiles(m, extras, l)
	if err != nil {
		return nil, err
	}
	if t == nil {
		return out, nil
	}
	target, ok := reg.Get(t.Type)
	if !ok {
		return nil, fmt.Errorf("targets: unknown type %q", t.Type)
	}
	ft, ok := target.(FileTarget)
	if !ok {
		return nil, fmt.Errorf("targets: type %q is not a file target", t.Type)
	}
	tf, err := ft.Files(Request{CertName: certName, Names: names, Material: m, Config: t.Config})
	if err != nil {
		return nil, err
	}
	return append(out, tf...), nil
}
