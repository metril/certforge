package targets

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/metril/certforge/internal/meta"
)

// fakeEitherTarget is a minimal Target fixture with a non-default
// Mode/KeyPolicy (Either/Optional), local to this test: targetstest cannot
// be imported here (it imports this package itself).
type fakeEitherTarget struct{}

func (fakeEitherTarget) Type() string                                    { return "test-either-optional" }
func (fakeEitherTarget) Name() string                                    { return "Test" }
func (fakeEitherTarget) Schema() json.RawMessage                         { return json.RawMessage(`{}`) }
func (fakeEitherTarget) RunsOn() Mode                                    { return Either }
func (fakeEitherTarget) KeyPolicy() KeyPolicy                            { return Optional }
func (fakeEitherTarget) Parse(json.RawMessage) (Config, error)           { return Config{}, nil }
func (fakeEitherTarget) Deploy(context.Context, Request) (Result, error) { return Result{}, nil }

// TestMetaDeployTargetAttrs covers AddToMeta: every registered type's
// meta.Entry carries Attrs{runsOn, keyPolicy} matching its own RunsOn/
// KeyPolicy.
func TestMetaDeployTargetAttrs(t *testing.T) {
	reg := NewRegistry()
	reg.Register(Traefik{})
	reg.Register(fakeEitherTarget{})
	metaReg := meta.NewRegistry()
	AddToMeta(reg, metaReg)

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
	if a := byCode["test-either-optional"].Attrs; a["runsOn"] != "either" || a["keyPolicy"] != "optional" {
		t.Fatalf("test-either-optional attrs = %+v", a)
	}
}
