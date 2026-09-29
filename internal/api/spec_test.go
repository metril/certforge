package api

import (
	"io/fs"
	"os"
	"path/filepath"
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

func TestPhase5OperationsDeclared(t *testing.T) {
	sw, err := gen.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, id := range []string{"rotateCa", "revokeCertificateVersion", "getKeysStatus", "startRewrap",
		"testVaultSettings", "createServerGrant", "listTargetGrants"} {
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
	if got := len(sw.Components.Schemas["CaType"].Value.Enum); got != 3 {
		t.Errorf("CaType has %d values, want 3", got)
	}
	if !slices.Contains(sw.Components.Schemas["RunsOn"].Value.Enum, "server") {
		t.Error("RunsOn missing server")
	}
	for _, f := range []string{"type", "config", "storedSecrets"} {
		if !slices.Contains(sw.Components.Schemas["CA"].Value.Required, f) {
			t.Errorf("CA.required missing %s", f)
		}
	}
	for _, f := range []string{"runsOn", "serverDeployment"} {
		if !slices.Contains(sw.Components.Schemas["Grant"].Value.Required, f) {
			t.Errorf("Grant.required missing %s", f)
		}
	}
}

func TestPhase6OperationsDeclared(t *testing.T) {
	sw, err := gen.GetSwagger()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, id := range []string{
		"listChannels", "createChannel", "getChannel", "updateChannel", "deleteChannel", "testChannel",
		"listMonitors", "createMonitor", "getMonitor", "updateMonitor", "deleteMonitor", "checkMonitor",
		"listEvents", "createBackup", "getBackupStatus", "testSmtpSettings", "getServerInfo",
	} {
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
	wantEventKinds := []string{
		"cert.issued", "cert.renewal_failed", "cert.expiring", "cert.expired",
		"deploy.failed", "deploy.drift", "client.offline", "agent.cert_expiring",
		"monitor.mismatch", "monitor.unreachable", "monitor.expiring", "monitor.recovered",
		"backup.completed", "backup.failed", "test",
	}
	if got := sw.Components.Schemas["EventKind"].Value.Enum; len(got) != len(wantEventKinds) {
		t.Errorf("EventKind has %d values, want %d", len(got), len(wantEventKinds))
	} else {
		for i, k := range wantEventKinds {
			if got[i] != k {
				t.Errorf("EventKind[%d] = %v, want %s", i, got[i], k)
			}
		}
	}
	if got := len(sw.Components.Schemas["ChannelType"].Value.Enum); got != 5 {
		t.Errorf("ChannelType has %d values, want 5", got)
	}
	for _, f := range []string{"summary", "storedSecrets", "lastDelivery"} {
		if !slices.Contains(sw.Components.Schemas["Channel"].Value.Required, f) {
			t.Errorf("Channel.required missing %s", f)
		}
	}
	rewrapTables := sw.Components.Schemas["RewrapTable"].Value.Enum
	if len(rewrapTables) == 0 || rewrapTables[len(rewrapTables)-1] != "notification_channels" {
		t.Errorf("RewrapTable does not end with notification_channels: %v", rewrapTables)
	}
}

// TestNoStubsRemain proves internal/api/phase5_stubs.go and
// internal/api/phase6_stubs.go (Tasks 2's and Phase 6A Task 2's 501
// placeholders) are both gone and nothing else in the package answers with
// a stub 501: every operationId's *Server method is a real handler now
// that Tasks 5-14 have landed. Mirrors the acceptance check `grep -rn "Not
// implemented" internal/api`, and (batch 6 review) also fails on a literal
// `StatusNotImplemented` anywhere in the package — the brief's actual
// requirement is no 501 handler at all, not just none using this string.
//
// internal/api/client/ (the generated client, Task 2's own
// oapi-codegen.client.yaml target) is skipped permanently below: it is
// generated, not a handler stub.
func TestNoStubsRemain(t *testing.T) {
	if _, err := os.Stat("phase5_stubs.go"); err == nil {
		t.Fatal("internal/api/phase5_stubs.go still exists")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if _, err := os.Stat("phase6_stubs.go"); err == nil {
		t.Fatal("internal/api/phase6_stubs.go still exists")
	} else if !os.IsNotExist(err) {
		t.Fatal(err)
	}
	err := filepath.WalkDir(".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// gen/ is oapi-codegen output: it always emits an "Unimplemented"
		// fallback StrictServerInterface (returning StatusNotImplemented
		// for every operation) as boilerplate, whether or not anything
		// wires it up — api.Server never does — so it is not a stub this
		// test can meaningfully flag. client/ is the generated Go client
		// (Task 2): also not a handler, never a stub.
		if d.IsDir() && (d.Name() == "gen" || d.Name() == "client") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(b), "Not implemented") {
			t.Errorf("%s: 501 stub remains", path)
		}
		if strings.Contains(string(b), "StatusNotImplemented") {
			t.Errorf("%s: StatusNotImplemented remains", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
