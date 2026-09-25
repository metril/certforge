//go:build unix

package agent

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestFileWriterChownAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	p := filepath.Join(t.TempDir(), "x.pem")
	if err := NewFileWriter(discard).Write(p, []byte("x"), 0o640, "65534", "65534"); err != nil {
		t.Fatal(err)
	}
	st, _ := os.Stat(p)
	if s := st.Sys().(*syscall.Stat_t); s.Uid != 65534 || s.Gid != 65534 {
		t.Fatalf("owner %d:%d", s.Uid, s.Gid)
	}
}
