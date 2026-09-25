package agent

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// resolveDeepestExisting cleans p, then resolves symlinks on its deepest
// existing ancestor directory and rejoins the remaining, not-yet-existing
// path components unresolved. A symlinked ancestor therefore cannot be used
// to make a path that looks confined resolve outside the allowed directory.
func resolveDeepestExisting(p string) (string, error) {
	dir := filepath.Clean(p)
	var suffix []string
	for {
		if _, err := os.Lstat(dir); err == nil {
			real, err := filepath.EvalSymlinks(dir)
			if err != nil {
				return "", err
			}
			for i := len(suffix) - 1; i >= 0; i-- {
				real = filepath.Join(real, suffix[i])
			}
			return real, nil
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no existing ancestor for %q", p)
		}
		suffix = append(suffix, filepath.Base(dir))
		dir = parent
	}
}

// confine checks that p, resolved through resolveDeepestExisting, falls
// under one of allow's directories (each independently resolved the same
// way, so a symlinked allow directory cannot be used to escape it either).
// An empty allow list always refuses. It returns the resolved path.
func confine(allow []string, p string) (string, error) {
	if len(allow) == 0 {
		return "", fmt.Errorf("%s: path not under CF_WRITE_ALLOW", p)
	}
	real, err := resolveDeepestExisting(p)
	if err != nil {
		return "", fmt.Errorf("%s: %w", p, err)
	}
	for _, a := range allow {
		areal, err := resolveDeepestExisting(a)
		if err != nil {
			continue
		}
		if real == areal {
			return real, nil
		}
		rel, err := filepath.Rel(areal, real)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return real, nil
		}
	}
	return "", fmt.Errorf("%s: path not under CF_WRITE_ALLOW", p)
}
