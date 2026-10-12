package internal_test

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// CertForge uses American English: "enroll", "organization". The only places
// the old spelling may remain are wire/stored values (audit actions
// client.enrol_*, the cf-enrol-* HMAC labels), which are allowlisted below.
var (
	badSpelling = regexp.MustCompile(`(?i)enrol([^le]|$)|organis`)
	allowedWire = regexp.MustCompile(`client\.enrol_|cf-enrol-`)
)

func TestAmericanSpelling(t *testing.T) {
	root := ".."
	skipDirs := map[string]bool{"node_modules": true, "dist": true, ".git": true, "migrations": true, "sqlcgen": true}
	var bad []string
	for _, top := range []string{"web/src", "web/e2e", "docs", "cmd", "internal", "api", "deploy", "test"} {
		_ = filepath.WalkDir(filepath.Join(root, top), func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				if skipDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			if strings.HasSuffix(p, "schema.d.ts") || strings.HasSuffix(p, "spelling_test.go") {
				return nil
			}
			b, err := os.ReadFile(p)
			if err != nil || strings.IndexByte(string(b), 0) >= 0 {
				return nil
			}
			for i, line := range strings.Split(string(b), "\n") {
				if badSpelling.MatchString(allowedWire.ReplaceAllString(line, "")) {
					bad = append(bad, p+":"+strconv.Itoa(i+1)+": "+strings.TrimSpace(line))
				}
			}
			return nil
		})
	}
	if len(bad) > 0 {
		t.Fatalf("British spelling found (use enroll/organization; wire values need client.enrol_ / cf-enrol- only):\n%s", strings.Join(bad, "\n"))
	}
}
