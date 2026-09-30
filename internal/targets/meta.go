package targets

import "github.com/metril/certforge/internal/meta"

// AddToMeta registers every target reg holds under meta.KindDeployTarget
// for GET /meta/schemas, each carrying Attrs{runsOn, keyPolicy} (Deviations
// R8/R9: read by the API into SchemaEntry.runsOn/keyPolicy starting Task 4;
// unread before that).
func AddToMeta(reg *Registry, metaReg *meta.Registry) {
	reg.Each(func(t Target) {
		metaReg.Add(meta.KindDeployTarget, meta.Entry{
			Code:   t.Type(),
			Name:   t.Name(),
			Schema: t.Schema(),
			Attrs:  map[string]string{"runsOn": string(t.RunsOn()), "keyPolicy": string(t.KeyPolicy())},
		})
	})
}
