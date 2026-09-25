package agent

import "github.com/metril/certforge/internal/agentproto"

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
