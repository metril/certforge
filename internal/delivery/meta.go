package delivery

import (
	"encoding/json"

	"github.com/metril/certforge/internal/meta"
)

// AddToMeta registers the deploy target schemas served at GET /meta/schemas.
func AddToMeta(r *meta.Registry) {
	r.Add(meta.KindDeployTarget, meta.Entry{Code: TargetTraefik, Name: "Traefik (file provider)", Schema: json.RawMessage(TraefikSchema)})
}
