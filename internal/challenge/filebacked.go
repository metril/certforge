package challenge

import (
	"os"
	"path/filepath"
)

// fileBacked maps a provider code to the file-backed credential fields it
// accepts: an inline schema key (holds the credential's own content, stored
// like any other secret) to the env var lego's provider actually reads (a
// server-side file path or location). Neither transip nor hyperone accepts
// its credential inline through lego's own env-var path; Build closes that
// gap by writing the inline value to a private temp file and pointing the
// provider's path env var at it instead, so the API never has to accept a
// path on the certforge server's own filesystem (SplitConfig keeps
// rejecting TRANSIP_PRIVATE_KEY_PATH/HYPERONE_PASSPORT_LOCATION directly).
var fileBacked = map[string]map[string]string{
	"transip":  {"TRANSIP_PRIVATE_KEY": "TRANSIP_PRIVATE_KEY_PATH"},
	"hyperone": {"HYPERONE_PASSPORT": "HYPERONE_PASSPORT_LOCATION"},
}

// withFileBackedCreds returns cfg unchanged (dir "") unless code has
// file-backed fields with a non-empty inline value present, in which case
// it returns a copy of cfg with each such inline key removed and replaced
// by its path env key pointing at a freshly written 0600 file inside a
// fresh, private 0700 temp directory (os.MkdirTemp's own default mode).
// The inline value itself is never written into cfg's path-keyed form, so
// it can never reach isolateEnv/os.Setenv.
//
// Both transip (gotransip.NewClient) and hyperone
// (internal.LoadPassportFile) read this file eagerly during provider
// construction and keep no reference to the path afterward, so the
// returned dir is safe for the caller to remove as soon as construction
// (successful or not) returns.
func withFileBackedCreds(code string, cfg map[string]string) (out map[string]string, dir string, err error) {
	fields, ok := fileBacked[code]
	if !ok {
		return cfg, "", nil
	}
	present := false
	for inline := range fields {
		if cfg[inline] != "" {
			present = true
			break
		}
	}
	if !present {
		return cfg, "", nil
	}

	dir, err = os.MkdirTemp("", "certforge-dns-*")
	if err != nil {
		return nil, "", err
	}
	out = make(map[string]string, len(cfg))
	for k, v := range cfg {
		out[k] = v
	}
	for inline, pathEnv := range fields {
		v := out[inline]
		if v == "" {
			continue
		}
		delete(out, inline)
		credPath := filepath.Join(dir, "cred")
		if err := os.WriteFile(credPath, []byte(v), 0o600); err != nil {
			os.RemoveAll(dir)
			return nil, "", err
		}
		out[pathEnv] = credPath
	}
	return out, dir, nil
}
