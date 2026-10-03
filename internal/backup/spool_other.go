//go:build !unix

package backup

import "os"

// lockFile is a no-op where flock is unavailable; the age threshold alone
// guards the stale sweep there.
func lockFile(*os.File) error { return nil }

func lockHeld(string) (bool, *os.File) { return false, nil }
