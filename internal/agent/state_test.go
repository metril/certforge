package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
)

func identityWithFile(t *testing.T, p string) *Identity {
	id := newTestIdentity(t)
	id.State.Grants[uuid.New()] = GrantState{Files: []agentproto.FileSpec{{Path: p}}}
	return id
}

func TestInstalledCachesDigests(t *testing.T) {
	p := filepath.Join(t.TempDir(), "a.pem")
	_ = os.WriteFile(p, []byte("one"), 0o644)
	id := identityWithFile(t, p)
	reads := 0
	old := readDigest
	readDigest = func(p string) (string, time.Time, error) { reads++; return fileDigest(p) }
	defer func() { readDigest = old }()

	first := id.Installed()
	id.Installed()
	if reads != 1 || first[0].SHA256 == "" {
		t.Fatalf("reads %d: unchanged file must not be read again", reads)
	}

	// Same size, new mtime: rehash.
	_ = os.WriteFile(p, []byte("two"), 0o644)
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(p, future, future)
	got := id.Installed()
	if reads != 2 || got[0].SHA256 == first[0].SHA256 {
		t.Fatalf("reads %d after an mtime change", reads)
	}

	// Same mtime, new size: rehash.
	_ = os.WriteFile(p, []byte("three"), 0o644)
	_ = os.Chtimes(p, future, future)
	id.Installed()
	if reads != 3 {
		t.Fatalf("reads %d after a size change", reads)
	}

	// Invalidated path: rehash.
	id.invalidate(p)
	id.Installed()
	if reads != 4 {
		t.Fatalf("reads %d after invalidate", reads)
	}

	// Missing file: empty digest, no read.
	_ = os.Remove(p)
	if got := id.Installed(); got[0].SHA256 != "" || reads != 4 {
		t.Fatalf("missing: %+v reads %d", got[0], reads)
	}
}
