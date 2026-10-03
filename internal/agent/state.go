package agent

import (
	"maps"

	"github.com/metril/certforge/internal/agentproto"
)

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
// after the lock is released.
func (id *Identity) Installed() []agentproto.InstalledFile {
	id.mu.Lock()
	snap := State{Grants: maps.Clone(id.State.Grants)}
	id.mu.Unlock()
	return snap.Installed()
}
