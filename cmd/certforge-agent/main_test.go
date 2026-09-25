package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCommands(t *testing.T) {
	data := t.TempDir()
	env := func(k string) string {
		if k == "CF_AGENT_DATA" {
			return data
		}
		return ""
	}
	var out, errb bytes.Buffer
	if code := run(nil, &out, &errb, env); code != 2 || !strings.Contains(errb.String(), "usage") {
		t.Fatalf("no args: %d %s", code, errb.String())
	}
	out.Reset()
	if code := run([]string{"version"}, &out, &errb, env); code != 0 || out.String() != "dev\n" {
		t.Fatalf("version: %d %q", code, out.String())
	}
	out.Reset()
	if code := run([]string{"status"}, &out, &errb, env); code != 0 || !strings.Contains(out.String(), "Not enrolled") {
		t.Fatalf("status: %d %q", code, out.String())
	}
	if code := run([]string{"enroll"}, &out, &errb, env); code != 2 {
		t.Fatalf("enroll without token: %d", code)
	}
	if code := run([]string{"bogus"}, &out, &errb, env); code != 2 {
		t.Fatalf("bogus: %d", code)
	}
}
