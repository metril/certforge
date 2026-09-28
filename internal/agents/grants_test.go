package agents

import (
	"testing"

	"github.com/google/uuid"
)

// TestClientOf covers the nullable client_id -> client id helper every
// grants.go path uses instead of dereferencing *ClientID directly: a
// server grant (client_id NULL, from migration 00012) must return an
// internal error, never panic.
func TestClientOf(t *testing.T) {
	id := uuid.New()
	got, err := clientOf(&id)
	if err != nil {
		t.Fatalf("clientOf(&id): %v", err)
	}
	if got != id {
		t.Fatalf("clientOf(&id) = %v, want %v", got, id)
	}

	if _, err := clientOf(nil); err == nil {
		t.Fatal("clientOf(nil) = nil error, want an error")
	}
}
