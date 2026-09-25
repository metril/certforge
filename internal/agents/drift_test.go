package agents

import (
	"strings"
	"testing"

	"github.com/metril/certforge/internal/agentproto"
)

var exp = []agentproto.FileSpec{{Path: "/a", SHA256: "1"}, {Path: "/b", SHA256: "2"}}

func digests(pairs ...string) []agentproto.FileDigest {
	var out []agentproto.FileDigest
	for i := 0; i < len(pairs); i += 2 {
		out = append(out, agentproto.FileDigest{Path: pairs[i], SHA256: pairs[i+1]})
	}
	return out
}

func TestReportState(t *testing.T) {
	if s, _, _, _ := ReportState(agentproto.GrantResult{State: "ok", Installed: digests("/a", "1", "/b", "2")}, exp); s != "ok" {
		t.Fatalf("match = %s", s)
	}
	if s, _, missing, mm := ReportState(agentproto.GrantResult{State: "ok", Installed: digests("/a", "9")}, exp); s != "drift" ||
		strings.Join(missing, ",") != "/b" || strings.Join(mm, ",") != "/a" {
		t.Fatalf("mismatch = %s %v %v", s, missing, mm)
	}
	if s, e, _, _ := ReportState(agentproto.GrantResult{State: "failed"}, exp); s != "failed" || e == "" {
		t.Fatalf("failed = %s %q", s, e)
	}
	if _, e, _, _ := ReportState(agentproto.GrantResult{State: "failed", Error: strings.Repeat("é", 3000)}, exp); len(e) > 2048 {
		t.Fatalf("error not capped: %d", len(e))
	}
	if s, _, _, _ := ReportState(agentproto.GrantResult{State: "bogus"}, exp); s != "failed" {
		t.Fatalf("unknown state = %s", s)
	}
}

func TestHeartbeatState(t *testing.T) {
	for _, tc := range []struct {
		cur, want string
		in        []agentproto.FileDigest
	}{
		{"pending", "pending", nil},
		{"failed", "failed", digests("/a", "1", "/b", "2")},
		{"ok", "ok", digests("/a", "1", "/b", "2")},
		{"ok", "drift", digests("/a", "1")},
		{"ok", "drift", digests("/a", "1", "/b", "")},
		{"drift", "ok", digests("/a", "1", "/b", "2")},
	} {
		if got, _, _ := HeartbeatState(tc.cur, exp, tc.in); got != tc.want {
			t.Errorf("%s + %v = %s, want %s", tc.cur, tc.in, got, tc.want)
		}
	}
}
