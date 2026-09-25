package authn

import (
	"testing"

	"github.com/google/uuid"
)

func TestActorIDAgent(t *testing.T) {
	id := uuid.New()
	p := Principal{Kind: KindAgent, ClientID: id, OrgID: uuid.New()}
	if p.ActorID() != id.String() {
		t.Fatalf("ActorID = %s", p.ActorID())
	}
}
