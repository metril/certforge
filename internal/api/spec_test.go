package api

import (
	"slices"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/metril/certforge/internal/api/gen"
)

func TestSpecDocumentsProblems(t *testing.T) {
	sw, err := gen.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	for path, item := range sw.Paths.Map() {
		for method, op := range item.Operations() {
			name := method + " " + path
			if op.Description == "" {
				t.Errorf("%s: no description", name)
			}
			want := []string{"500"}
			if op.Security == nil || len(*op.Security) > 0 {
				want = append(want, "401", "403")
			}
			if op.RequestBody != nil {
				want = append(want, "400", "413", "415", "422")
			}
			params := slices.Concat(item.Parameters, op.Parameters)
			if slices.ContainsFunc(params, func(p *openapi3.ParameterRef) bool { return p.Value.In == "path" }) {
				want = append(want, "404")
			}
			if slices.ContainsFunc(params, func(p *openapi3.ParameterRef) bool { return p.Value.In == "query" }) {
				want = append(want, "400")
			}
			for _, code := range want {
				r := op.Responses.Value(code)
				if r == nil || r.Value == nil || r.Value.Content.Get("application/problem+json") == nil {
					t.Errorf("%s: missing problem+json %s", name, code)
				}
			}
		}
	}
}

func TestSpecDescribesEveryField(t *testing.T) {
	sw, err := gen.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range sw.Components.Schemas {
		if s.Value.Description == "" {
			t.Errorf("schema %s: no description", name)
		}
		for prop, ps := range s.Value.Properties {
			if ps.Value.Description == "" && !strings.HasPrefix(ps.Ref, "#/") {
				t.Errorf("schema %s.%s: no description", name, prop)
			}
		}
	}
}
