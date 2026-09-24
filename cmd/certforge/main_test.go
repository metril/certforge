package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestRunHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"help"}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d, want 0", code)
	}
	if !strings.Contains(out.String(), "version") {
		t.Fatalf("usage missing commands: %q", out.String())
	}
}

func TestRunNoArgs(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), nil, &out, &errOut); code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
}

func TestRunUnknown(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"nope"}, &out, &errOut); code != 2 {
		t.Fatalf("code = %d, want 2", code)
	}
	if !strings.Contains(errOut.String(), `unknown command "nope"`) {
		t.Fatalf("stderr = %q", errOut.String())
	}
}

func TestRunVersion(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &out, &errOut); code != 0 {
		t.Fatalf("code = %d", code)
	}
	if out.String() != "dev\n" {
		t.Fatalf("out = %q", out.String())
	}
}
