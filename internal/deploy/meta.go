package deploy

import "github.com/metril/certforge/internal/meta"

// AddToMeta registers every target reg holds under meta.KindDeployTarget
// for GET /meta/schemas.
func AddToMeta(reg *Registry, metaReg *meta.Registry) {
	reg.each(func(typ string, e regEntry) {
		metaReg.Add(meta.KindDeployTarget, meta.Entry{Code: typ, Name: e.name, Schema: e.target.Schema()})
	})
}
