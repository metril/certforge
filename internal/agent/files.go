package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"os/user"
	"strconv"
	"sync/atomic"
	"time"
)

// FileWriter installs files atomically with mode, and owner/group when the
// agent runs as root (otherwise it warns once and applies the mode only).
type FileWriter struct {
	Log    *slog.Logger
	EUID   int
	Lookup func(owner, group string) (uid, gid int, err error)
	warned atomic.Bool
}

// NewFileWriter uses the process's effective uid and the system user database.
func NewFileWriter(log *slog.Logger) *FileWriter {
	return &FileWriter{Log: log, EUID: os.Geteuid(), Lookup: lookupIDs}
}

// chownFor returns the chown step for owner and group: nil when neither is
// set, or (with a one-time warning) when not root.
func (w *FileWriter) chownFor(owner, group string) (func(*os.File) error, error) {
	if owner == "" && group == "" {
		return nil, nil
	}
	if w.EUID != 0 {
		if w.warned.CompareAndSwap(false, true) {
			w.Log.Warn("not running as root: layout owner and group are ignored, only modes are applied")
		}
		return nil, nil
	}
	uid, gid, err := w.Lookup(owner, group)
	if err != nil {
		return nil, fmt.Errorf("owner %q group %q: %w", owner, group, err)
	}
	return func(f *os.File) error { return f.Chown(uid, gid) }, nil
}

// Write installs data at p (temp file, fsync, chmod, chown, rename).
func (w *FileWriter) Write(p string, data []byte, mode fs.FileMode, owner, group string) error {
	chown, err := w.chownFor(owner, group)
	if err != nil {
		return err
	}
	return writeAtomic(p, data, mode, chown)
}

// Stage is the first half of Write: it prepares a temp sibling of p with
// the final content, mode and ownership and returns its path, leaving p
// untouched. Commit it with Commit or drop it with Discard.
func (w *FileWriter) Stage(p string, data []byte, mode fs.FileMode, owner, group string) (string, error) {
	chown, err := w.chownFor(owner, group)
	if err != nil {
		return "", err
	}
	return stageAtomic(p, data, mode, chown)
}

// Commit renames a staged temp over p.
func (w *FileWriter) Commit(tmp, p string) error { return commitStaged(tmp, p) }

// Discard removes a staged temp.
func (w *FileWriter) Discard(tmp string) { _ = os.Remove(tmp) }

// Remove deletes p; a missing file is not an error.
func (w *FileWriter) Remove(p string) error {
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// lookupIDs resolves names or numeric ids; -1 leaves that id unchanged.
func lookupIDs(owner, group string) (int, int, error) {
	uid, gid := -1, -1
	if owner != "" {
		if n, err := strconv.Atoi(owner); err == nil {
			uid = n
		} else {
			u, err := user.Lookup(owner)
			if err != nil {
				return 0, 0, err
			}
			uid, _ = strconv.Atoi(u.Uid)
		}
	}
	if group != "" {
		if n, err := strconv.Atoi(group); err == nil {
			gid = n
		} else {
			g, err := user.LookupGroup(group)
			if err != nil {
				return 0, 0, err
			}
			gid, _ = strconv.Atoi(g.Gid)
		}
	}
	return uid, gid, nil
}

// fileDigest returns p's content sha256 and mtime; "" when p is missing.
func fileDigest(p string) (string, time.Time, error) {
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return "", time.Time{}, nil
	}
	if err != nil {
		return "", time.Time{}, err
	}
	st, err := os.Stat(p)
	if err != nil {
		return "", time.Time{}, err
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:]), st.ModTime().UTC(), nil
}
