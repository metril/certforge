package agentproto

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
)

// An older agent decodes this exact shape: field names and order must not change.
func TestHookSpecJSONShape(t *testing.T) {
	id := uuid.MustParse("11111111-1111-1111-1111-111111111111")
	b, _ := json.Marshal(HookSpec{ID: id, Phase: "post_deploy", Argv: []string{"/bin/true"}, TimeoutSeconds: 60})
	if want := `{"id":"` + id.String() + `","phase":"post_deploy","argv":["/bin/true"],"timeoutSeconds":60}`; string(b) != want {
		t.Fatalf("exec: %s", b)
	}
	b, _ = json.Marshal(HookSpec{ID: id, Phase: "post_deploy", Kind: "restart", Target: "docker:web", TimeoutSeconds: 30})
	if want := `{"id":"` + id.String() + `","phase":"post_deploy","argv":null,"kind":"restart","target":"docker:web","timeoutSeconds":30}`; string(b) != want {
		t.Fatalf("restart: %s", b)
	}
}
