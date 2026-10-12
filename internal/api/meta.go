package api

import (
	"bytes"
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
	if out.DeployCredentials, err = s.schemaEntries(meta.KindDeployCredential); err != nil {
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

// propertyOrder returns the top-level "properties" keys of a JSON Schema in
// source order. Decoding the schema into a map (for the generated response
// type) sorts keys alphabetically and loses the author's field order, so the
// order is sent separately as "x-order" for the UI to apply.
func propertyOrder(raw json.RawMessage) []string {
	var doc struct {
		Properties json.RawMessage `json:"properties"`
	}
	if json.Unmarshal(raw, &doc) != nil || len(doc.Properties) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(doc.Properties))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	var keys []string
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil
		}
		k, ok := t.(string)
		if !ok {
			return nil
		}
		keys = append(keys, k)
		var skip json.RawMessage
		if dec.Decode(&skip) != nil {
			return nil
		}
	}
	return keys
}

func (s *Server) schemaEntries(k meta.Kind) ([]gen.SchemaEntry, error) {
	entries := s.d.Meta.List(k)
	out := make([]gen.SchemaEntry, 0, len(entries))
	for _, e := range entries {
		var schema map[string]interface{}
		if err := json.Unmarshal(e.Schema, &schema); err != nil {
			return nil, fmt.Errorf("meta %s/%s: %w", k, e.Code, err)
		}
		if order := propertyOrder(e.Schema); len(order) > 0 {
			schema["x-order"] = order
		}
		se := gen.SchemaEntry{Code: e.Code, Name: e.Name, Schema: schema}
		if len(e.Aliases) > 0 {
			se.Aliases = &e.Aliases
		}
		if len(e.GrantSchema) > 0 {
			var gs map[string]interface{}
			if err := json.Unmarshal(e.GrantSchema, &gs); err != nil {
				return nil, fmt.Errorf("meta %s/%s grantSchema: %w", k, e.Code, err)
			}
			se.GrantSchema = &gs
		}
		// e.Attrs is set only for KindDeployTarget entries
		// (targets.AddToMeta); every other kind's Attrs is nil, so runsOn
		// and keyPolicy stay unset here too.
		if v, ok := e.Attrs["runsOn"]; ok {
			runsOn := gen.TargetRunsOn(v)
			se.RunsOn = &runsOn
		}
		if v, ok := e.Attrs["keyPolicy"]; ok {
			keyPolicy := gen.KeyPolicy(v)
			se.KeyPolicy = &keyPolicy
		}
		out = append(out, se)
	}
	return out, nil
}
