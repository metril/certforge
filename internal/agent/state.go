package agent

import (
	"errors"
	"io/fs"
	"maps"
	"os"
	"time"

	"github.com/metril/certforge/internal/agentproto"
)

// readDigest hashes a file; a seam so tests can count reads.
var readDigest = fileDigest

// cachedDigest is a file's digest with the stat it was taken under.
type cachedDigest struct {
	SHA256 string
	MTime  time.Time
	Size   int64
}

// Installed re-reads every installed file for the heartbeat; a missing
// file has an empty digest.
func (s *State) Installed() []agentproto.InstalledFile {
	out := []agentproto.InstalledFile{}
	for id, g := range s.Grants {
		for _, f := range g.Files {
			sum, mt, _ := fileDigest(f.Path)
			out = append(out, agentproto.InstalledFile{GrantID: id, Path: f.Path, SHA256: sum, MTime: mt})
		}
	}
	return out
}

// Installed is State.Installed over a snapshot taken under the identity's
// lock, so it is safe beside a running reconcile; the file reads happen
// after the lock is released. A file is rehashed only when its mtime or size
// changed since the cached digest, or on a cache miss or stat error.
func (id *Identity) Installed() []agentproto.InstalledFile {
	id.mu.Lock()
	snap := State{Grants: maps.Clone(id.State.Grants)}
	id.mu.Unlock()
	out := []agentproto.InstalledFile{}
	for gid, g := range snap.Grants {
		for _, f := range g.Files {
			sum, mt := id.digest(f.Path)
			out = append(out, agentproto.InstalledFile{GrantID: gid, Path: f.Path, SHA256: sum, MTime: mt})
		}
	}
	return out
}

// digest returns p's digest, from the cache when a stat matches it.
func (id *Identity) digest(p string) (string, time.Time) {
	st, err := os.Stat(p)
	if errors.Is(err, fs.ErrNotExist) {
		id.dmu.Lock()
		delete(id.digests, p)
		id.dmu.Unlock()
		return "", time.Time{}
	}
	if err == nil {
		id.dmu.Lock()
		c, ok := id.digests[p]
		id.dmu.Unlock()
		if ok && c.Size == st.Size() && c.MTime.Equal(st.ModTime()) {
			return c.SHA256, c.MTime.UTC()
		}
	}
	// The stat above predates the read, so a change in between leaves a
	// stale stat in the cache and forces a rehash next time.
	sum, mt, derr := readDigest(p)
	if derr != nil || err != nil {
		return sum, mt
	}
	id.dmu.Lock()
	if id.digests == nil {
		id.digests = map[string]cachedDigest{}
	}
	id.digests[p] = cachedDigest{SHA256: sum, MTime: st.ModTime(), Size: st.Size()}
	id.dmu.Unlock()
	return sum, mt
}

// invalidate drops a path's cached digest (the watcher saw it change).
func (id *Identity) invalidate(p string) {
	id.dmu.Lock()
	delete(id.digests, p)
	id.dmu.Unlock()
}

// InstalledPaths lists every installed file path across grants.
func (id *Identity) InstalledPaths() []string {
	id.mu.Lock()
	defer id.mu.Unlock()
	var out []string
	for _, g := range id.State.Grants {
		for _, f := range g.Files {
			out = append(out, f.Path)
		}
	}
	return out
}
