//go:build unix

package backup

import (
	"os"
	"syscall"
)

// lockFile takes a non-blocking exclusive flock on f.
func lockFile(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

// lockHeld reports whether another process or backup holds the flock on
// path. A missing lock file is not held. When not held, the returned file
// keeps the probe lock until the caller closes it.
func lockHeld(path string) (bool, *os.File) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false, nil
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return err == syscall.EWOULDBLOCK, nil
	}
	return false, f
}
