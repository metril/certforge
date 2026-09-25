package delivery

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/metril/certforge/internal/agentproto"
)

// Digest is the lowercase hex SHA-256 of b.
func Digest(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Specs turns rendered files into the expected-file list sent to agents.
func Specs(files []File) []agentproto.FileSpec {
	out := make([]agentproto.FileSpec, 0, len(files))
	for _, f := range files {
		out = append(out, agentproto.FileSpec{Path: f.Path, Owner: f.Owner, Group: f.Group, Mode: f.Mode, SHA256: Digest(f.Data)})
	}
	return out
}

// Compare lists expected paths missing from installed (absent or empty
// digest) and paths whose digest differs. Extra installed paths are ignored.
func Compare(expected []agentproto.FileSpec, installed []agentproto.FileDigest) (missing, mismatched []string) {
	have := make(map[string]string, len(installed))
	for _, f := range installed {
		have[f.Path] = f.SHA256
	}
	for _, e := range expected {
		got, ok := have[e.Path]
		switch {
		case !ok || got == "":
			missing = append(missing, e.Path)
		case got != e.SHA256:
			mismatched = append(mismatched, e.Path)
		}
	}
	return missing, mismatched
}
