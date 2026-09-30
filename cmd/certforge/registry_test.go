package main

import (
	"testing"

	"github.com/metril/certforge/internal/agent"
	"github.com/metril/certforge/internal/meta"
	"github.com/metril/certforge/internal/targets"
)

// These tests call the actual production registry constructors —
// newTargetsRegistry (serve.go) and agent.NewTargetsRegistry — rather than
// reimplementing the wiring themselves (batch-1 review): a test type
// accidentally registered into either would otherwise go uncaught.

func registryCodes(reg *targets.Registry) []string {
	var codes []string
	reg.Each(func(t targets.Target) { codes = append(codes, t.Type()) })
	return codes
}

// TestProductRegistriesHaveNoTestTypes guards the server and agent
// registries against ever holding a targetstest type: exactly {traefik,
// vault-kv} and {traefik}, respectively.
func TestProductRegistriesHaveNoTestTypes(t *testing.T) {
	if got := registryCodes(newTargetsRegistry(nil)); len(got) != 2 || got[0] != "traefik" || got[1] != "vault-kv" {
		t.Fatalf("server registry codes = %v, want [traefik vault-kv]", got)
	}
	if got := registryCodes(agent.NewTargetsRegistry()); len(got) != 1 || got[0] != "traefik" {
		t.Fatalf("agent registry codes = %v, want [traefik]", got)
	}
}

// TestAgentRegistryHasNoVaultKV covers the agent-shape registry
// specifically: vault-kv (server-run) is absent.
func TestAgentRegistryHasNoVaultKV(t *testing.T) {
	if _, ok := agent.NewTargetsRegistry().Get("vault-kv"); ok {
		t.Fatal("agent registry holds vault-kv")
	}
	if _, ok := agent.NewTargetsRegistry().Get("traefik"); !ok {
		t.Fatal("agent registry is missing traefik")
	}
}

// TestRegistryModesMatrix covers every product type's fixed RunsOn/
// KeyPolicy: traefik always runs on the agent and always needs the key;
// vault-kv always runs on the server and only needs the key when its own
// config's includeKey does (Optional).
func TestRegistryModesMatrix(t *testing.T) {
	reg := newTargetsRegistry(nil)
	cases := []struct {
		typ       string
		runsOn    targets.Mode
		keyPolicy targets.KeyPolicy
	}{
		{"traefik", targets.Agent, targets.Always},
		{"vault-kv", targets.Server, targets.Optional},
	}
	for _, c := range cases {
		target, ok := reg.Get(c.typ)
		if !ok {
			t.Fatalf("%s: not registered", c.typ)
		}
		if target.RunsOn() != c.runsOn {
			t.Errorf("%s: RunsOn = %s, want %s", c.typ, target.RunsOn(), c.runsOn)
		}
		if target.KeyPolicy() != c.keyPolicy {
			t.Errorf("%s: KeyPolicy = %s, want %s", c.typ, target.KeyPolicy(), c.keyPolicy)
		}
	}
}

// TestMetaDeployTargetAttrs covers targets.AddToMeta wired the way
// serve.go wires it: every product type's meta.Entry carries
// Attrs{runsOn, keyPolicy} matching its own RunsOn/KeyPolicy.
func TestMetaDeployTargetAttrs(t *testing.T) {
	reg := newTargetsRegistry(nil)
	metaReg := meta.NewRegistry()
	targets.AddToMeta(reg, metaReg)

	entries := metaReg.List(meta.KindDeployTarget)
	if len(entries) != 2 {
		t.Fatalf("entries = %+v", entries)
	}
	byCode := map[string]meta.Entry{}
	for _, e := range entries {
		byCode[e.Code] = e
	}
	if a := byCode["traefik"].Attrs; a["runsOn"] != "agent" || a["keyPolicy"] != "always" {
		t.Fatalf("traefik attrs = %+v", a)
	}
	if a := byCode["vault-kv"].Attrs; a["runsOn"] != "server" || a["keyPolicy"] != "optional" {
		t.Fatalf("vault-kv attrs = %+v", a)
	}
	if byCode["vault-kv"].Name != "Vault KV" || byCode["traefik"].Name != "Traefik" {
		t.Fatalf("display names: traefik=%q vault-kv=%q", byCode["traefik"].Name, byCode["vault-kv"].Name)
	}
}
