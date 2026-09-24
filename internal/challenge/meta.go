package challenge

import "github.com/metril/certforge/internal/meta"

// AddToMeta publishes every DNS provider under meta.KindDNSProvider for
// GET /api/v1/meta/schemas.
func AddToMeta(r *meta.Registry) {
	for _, p := range Providers() {
		r.Add(meta.KindDNSProvider, meta.Entry{Code: p.Code, Name: p.Name, Schema: p.Schema, Aliases: p.Aliases})
	}
}
