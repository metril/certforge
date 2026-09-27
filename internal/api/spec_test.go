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

func TestPhase3OperationsDeclared(t *testing.T) {
	sw, err := gen.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, id := range []string{"listClients", "createClient", "listAllClients", "getClient", "updateClient", "deleteClient",
		"revokeClient", "reenrollClient", "listClientGrants", "createGrant", "updateGrant", "deleteGrant", "redeployGrant",
		"listClientHookRuns", "listCertificateDeployments", "listLayouts", "createLayout", "getLayout", "updateLayout",
		"deleteLayout", "listDeployTargets", "createDeployTarget", "getDeployTarget", "updateDeployTarget",
		"deleteDeployTarget", "listHooks", "createHook", "getHook", "updateHook", "deleteHook", "listAgentCAs",
		"rotateAgentCA", "retireAgentCA"} {
		want[id] = false
	}
	// oapi-codegen's embedded spec normalizes operationId to its generated Go
	// method name (initial letter upper-cased); lower-case it back to compare
	// against the operationId as written in api/openapi.yaml.
	for _, item := range sw.Paths.Map() {
		for _, op := range item.Operations() {
			id := op.OperationID
			if id != "" {
				id = strings.ToLower(id[:1]) + id[1:]
			}
			if _, ok := want[id]; ok {
				want[id] = true
			}
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("operation %s missing", id)
		}
	}
	if sw.Components.Schemas["Certificate"].Value.Properties["grantCount"] == nil {
		t.Error("Certificate.grantCount missing")
	}
}

func TestPhase4OperationsDeclared(t *testing.T) {
	sw, err := gen.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, id := range []string{"exportCertificateVersion", "uploadCertificate", "uploadCertificateVersion",
		"importCertificates", "getRateLedger"} {
		want[id] = false
	}
	// See TestPhase3OperationsDeclared for why the operationId is lower-cased
	// back before comparing against api/openapi.yaml.
	for _, item := range sw.Paths.Map() {
		for _, op := range item.Operations() {
			id := op.OperationID
			if id != "" {
				id = strings.ToLower(id[:1]) + id[1:]
			}
			if _, ok := want[id]; ok {
				want[id] = true
			}
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("operation %s missing", id)
		}
	}
	if got := len(sw.Components.Schemas["OutputFormat"].Value.Enum); got != 4 {
		t.Errorf("OutputFormat has %d values, want 4", got)
	}
	if got := len(sw.Components.Schemas["VerificationRule"].Value.Properties["method"].Value.Enum); got != 4 {
		t.Errorf("VerificationRule.method has %d values, want 4", got)
	}
	if !slices.Contains(sw.Components.Schemas["Certificate"].Value.Required, "managed") {
		t.Error("Certificate.required missing managed")
	}
	if !slices.Contains(sw.Components.Schemas["CertificateVersion"].Value.Required, "hasKey") {
		t.Error("CertificateVersion.required missing hasKey")
	}
}
