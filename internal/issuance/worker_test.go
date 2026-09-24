package issuance

import (
	"strings"
	"testing"
)

// TestTruncatedStackCap is the Review Focus for the fix-round bound on the
// panic path: a full stack trace can run to tens of KiB (deep recursion, or
// many goroutines dumped by some runtimes) and would otherwise dominate a
// Timeline's own 64 KiB log cap on its own.
func TestTruncatedStackCap(t *testing.T) {
	s := truncatedStack()
	if len(s) > maxPanicStackBytes+64 {
		t.Fatalf("stack is %d bytes, want at most ~%d", len(s), maxPanicStackBytes)
	}
	// A real call stack always has at least a frame or two; the trace itself
	// should never be empty (a bug here would defeat the point of logging it).
	if !strings.Contains(string(s), "goroutine") {
		t.Fatalf("does not look like a stack trace: %q", s[:min(len(s), 200)])
	}
}

func TestTruncateBytesCapsAndMarks(t *testing.T) {
	big := strings.Repeat("a", maxPanicStackBytes*3)
	out := truncateBytes([]byte(big), maxPanicStackBytes)
	if len(out) > maxPanicStackBytes+32 {
		t.Fatalf("truncated = %d bytes, want at most ~%d", len(out), maxPanicStackBytes)
	}
	if !strings.HasSuffix(string(out), "[stack truncated]") {
		t.Fatalf("missing truncation marker: %q", out[len(out)-40:])
	}
	small := []byte("short")
	if got := truncateBytes(small, maxPanicStackBytes); string(got) != "short" {
		t.Fatalf("short input was modified: %q", got)
	}
}
