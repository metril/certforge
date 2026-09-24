package api

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/meta"
)

// GetMetaSchemas returns all registered pluggable type schemas.
func (s *Server) GetMetaSchemas(ctx context.Context, _ gen.GetMetaSchemasRequestObject) (gen.GetMetaSchemasResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionOrgsRead, nil); err != nil {
		return nil, err
	}
	var out gen.MetaSchemas
	var err error
	if out.DnsProviders, err = s.schemaEntries(meta.KindDNSProvider); err != nil {
		return nil, err
	}
	if out.DeployTargets, err = s.schemaEntries(meta.KindDeployTarget); err != nil {
		return nil, err
	}
	if out.Notifiers, err = s.schemaEntries(meta.KindNotifier); err != nil {
		return nil, err
	}
	if out.Signers, err = s.schemaEntries(meta.KindSigner); err != nil {
		return nil, err
	}
	return gen.GetMetaSchemas200JSONResponse(out), nil
}

func (s *Server) schemaEntries(k meta.Kind) ([]gen.SchemaEntry, error) {
	entries := s.d.Meta.List(k)
	out := make([]gen.SchemaEntry, 0, len(entries))
	for _, e := range entries {
		var schema map[string]interface{}
		if err := json.Unmarshal(e.Schema, &schema); err != nil {
			return nil, fmt.Errorf("meta %s/%s: %w", k, e.Code, err)
		}
		out = append(out, gen.SchemaEntry{Code: e.Code, Name: e.Name, Schema: schema})
	}
	return out, nil
}
