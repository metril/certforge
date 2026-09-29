package notify

import "github.com/metril/certforge/internal/meta"

// AddToMeta registers every notifier reg holds under meta.KindNotifier for
// GET /api/v1/meta/schemas (Shared contract: "notifiers[] {code, name,
// schema}").
func AddToMeta(reg *Registry, metaReg *meta.Registry) {
	for _, typ := range reg.Types() {
		n, ok := reg.Get(typ)
		if !ok {
			continue
		}
		metaReg.Add(meta.KindNotifier, meta.Entry{Code: n.Type(), Name: n.Name(), Schema: n.Schema()})
	}
}
