package actions

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/targets"
)

const id1 = "11111111-1111-1111-1111-111111111111"

func TestParse(t *testing.T) {
	long := strings.Repeat("a", 513)
	cases := []struct{ kind, cfg, bad string }{
		{"exec", `{"argv":["/bin/true"]}`, ""},
		{"exec", `{"argv":[]}`, "argv"},
		{"exec", `{"argv":["true"]}`, "argv[0]"},
		{"exec", `{"argv":["/bin/true"],"x":1}`, "config"},
		{"restart", `{"target":"docker:web"}`, ""},
		{"restart", `{"target":"systemd:nginx.service"}`, ""},
		{"restart", `{"target":"pm2:web"}`, "target"},
		{"ssh", `{"targetId":"` + id1 + `","command":"ls"}`, ""},
		{"ssh", `{"targetId":"nope","command":"ls"}`, "targetId"},
		{"ssh", `{"targetId":"` + id1 + `","command":"` + long + `"}`, "command"},
		{"ssh", `{"targetId":"` + id1 + `","command":""}`, "command"},
		{"pfsense_shell", `{"targetId":"` + id1 + `","command":"ls"}`, ""},
		{"pfsense_restart", `{"targetId":"` + id1 + `"}`, ""},
		{"pfsense_restart", `{"targetId":"` + id1 + `","mode":"selected","services":["webgui"]}`, ""},
		{"pfsense_restart", `{"targetId":"` + id1 + `","mode":"selected"}`, "services"},
		{"pfsense_restart", `{"targetId":"` + id1 + `","mode":"some"}`, "mode"},
		{"pfsense_restart", `{"targetId":"` + id1 + `","mode":"selected","services":["package:a\");system(1);"]}`, "services"},
		{"pfsense_restart", `{"targetId":"` + id1 + `","mode":"selected","services":["webgui","webgui"]}`, "services"},
		{"pfsense_restart", `{"targetId":"` + id1 + `","mode":"all","services":["webgui"]}`, "services"},
		{"pfsense_restart", `{"targetId":"` + id1 + `","mode":"selected","services":["webgui","openvpn:server:1","package:acme"]}`, ""},
		{"truenas_restart", `{"targetId":"` + id1 + `"}`, ""},
		{"truenas_restart", `{}`, "targetId"},
		{"routeros_restart", `{"targetId":"` + id1 + `"}`, ""},
		{"http", `{"method":"GET","url":"https://x.example/h"}`, ""},
		{"http", `{"method":"GET","url":"ftp://x"}`, "url"},
		{"http", `{"method":"TRACE","url":"https://x"}`, "method"},
		{"http", `{"method":"GET","url":"https://x","body":"` + strings.Repeat("a", 8193) + `"}`, "body"},
		{"http", `{"method":"GET","url":"https://x","expectedStatus":{"min":300,"max":200}}`, "expectedStatus"},
		{"http", `{"method":"GET","url":"https://x","headers":{"bad name":"v"}}`, "headers"},
		{"notify", `{"channelId":"` + id1 + `"}`, ""},
		{"notify", `{"channelId":"x"}`, "channelId"},
		{"verify_tls", `{"host":"a.example"}`, ""},
		{"verify_tls", `{"host":"a.example","port":0}`, "port"},
		{"verify_tls", `{"host":"a.example","port":65536}`, "port"},
		{"verify_tls", `{"host":"","port":443}`, "host"},
		{"wait", `{"seconds":300}`, ""},
		{"wait", `{"seconds":0}`, "seconds"},
		{"wait", `{"seconds":301}`, "seconds"},
		{"wait", `[]`, "config"},
	}
	for _, c := range cases {
		k, ok := Default.Get(c.kind)
		if !ok {
			t.Fatalf("no kind %s", c.kind)
		}
		_, err := k.Parse(json.RawMessage(c.cfg))
		if c.bad == "" {
			if err != nil {
				t.Errorf("%s %s: %v", c.kind, c.cfg, err)
			}
			continue
		}
		var f *delivery.FieldError
		if !errors.As(err, &f) || f.Field != c.bad {
			t.Errorf("%s %s: got %v, want field %s", c.kind, c.cfg, err, c.bad)
		}
	}
}

func TestHTTPSecretSplit(t *testing.T) {
	k, _ := Default.Get("http")
	c, err := k.Parse(json.RawMessage(`{"method":"POST","url":"https://x","headers":{"A":"b"},"secretHeaders":{"Authorization":"Bearer s3"}}`))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(c.Public), "s3") || strings.Contains(string(c.Public), "secretHeaders") {
		t.Errorf("public leaks secret: %s", c.Public)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(c.Secrets["secretHeaders"]), &m); err != nil || m["Authorization"] != "Bearer s3" {
		t.Errorf("secrets = %v", c.Secrets)
	}
}

func TestRegistry(t *testing.T) {
	all := Default.All()
	if len(all) != 11 {
		t.Fatalf("kinds = %d", len(all))
	}
	for i, k := range all {
		if i > 0 && all[i-1].Code() >= k.Code() {
			t.Errorf("not sorted at %s", k.Code())
		}
		var s map[string]any
		if err := json.Unmarshal(k.Schema(), &s); err != nil || s["title"] == "" {
			t.Errorf("%s schema: %v", k.Code(), err)
		}
		wantTypes := strings.Contains(string(k.Schema()), `"targetId"`)
		if wantTypes != (len(k.TargetTypes()) > 0) {
			t.Errorf("%s target types mismatch", k.Code())
		}
		agent := k.Code() == "exec" || k.Code() == "restart"
		if agent != (k.RunsOn() == targets.Agent) {
			t.Errorf("%s runsOn %s", k.Code(), k.RunsOn())
		}
		hint := "post_deploy"
		if agent || k.Code() == "wait" {
			hint = ""
		}
		if k.PhaseHint() != hint {
			t.Errorf("%s hint %q", k.Code(), k.PhaseHint())
		}
	}
	if k, _ := Default.Get("http"); !strings.Contains(string(k.Schema()), `"secret": true`) {
		t.Error("http schema lacks secret marker")
	}
}

func u(n byte) uuid.UUID   { return uuid.UUID{15: n} }
func up(n byte) *uuid.UUID { x := u(n); return &x }

func TestParseSteps(t *testing.T) {
	good, err := ParseSteps(json.RawMessage(`[{"action":"` + u(1).String() + `"},{"group":"` + u(2).String() + `"}]`))
	if err != nil || len(good) != 2 || good[1].Group == nil {
		t.Fatalf("%v %v", good, err)
	}
	if s, err := ParseSteps(nil); err != nil || s != nil {
		t.Errorf("nil: %v %v", s, err)
	}
	both := `[{"action":"` + u(1).String() + `","group":"` + u(2).String() + `"}]`
	if _, err := ParseSteps(json.RawMessage(both)); err == nil || !strings.Contains(err.Error(), "steps[0]") {
		t.Errorf("both: %v", err)
	}
	if _, err := ParseSteps(json.RawMessage(`[{}]`)); err == nil {
		t.Error("empty step accepted")
	}
	one := `{"action":"` + u(1).String() + `"}`
	many := "[" + strings.Repeat(one+",", 32) + one + "]"
	if _, err := ParseSteps(json.RawMessage(many)); err == nil {
		t.Error("33 steps accepted")
	}
}

func TestExpand(t *testing.T) {
	look := func(id uuid.UUID) (ActionRef, bool) {
		if id == u(99) {
			return ActionRef{}, false
		}
		return ActionRef{ID: id, RunsOn: targets.Server}, true
	}
	groups := map[uuid.UUID][]uuid.UUID{u(50): {u(3), u(4)}}
	refs, err := Expand([]Step{{Action: up(1)}, {Group: up(50)}, {Action: up(2)}}, groups, look)
	if err != nil {
		t.Fatal(err)
	}
	var got []uuid.UUID
	for _, r := range refs {
		got = append(got, r.ID)
	}
	want := []uuid.UUID{u(1), u(3), u(4), u(2)}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("order %v", got)
		}
	}
	_, err = Expand([]Step{{Action: up(1)}, {Action: up(99)}}, groups, look)
	if err == nil || !strings.Contains(err.Error(), "steps[1]") {
		t.Errorf("unknown action: %v", err)
	}
	if _, err = Expand([]Step{{Group: up(77)}}, groups, look); err == nil || !strings.Contains(err.Error(), "steps[0]") {
		t.Errorf("unknown group: %v", err)
	}
	big := make([]uuid.UUID, 20)
	for i := range big {
		big[i] = u(1)
	}
	_, err = Expand([]Step{{Group: up(60)}, {Group: up(60)}}, map[uuid.UUID][]uuid.UUID{u(60): big}, look)
	if err == nil || !strings.Contains(err.Error(), "steps[1]") {
		t.Errorf("expanded limit: %v", err)
	}
}

func TestRunsOnMismatch(t *testing.T) {
	refs := []ActionRef{{RunsOn: targets.Agent}, {RunsOn: targets.Server}, {RunsOn: targets.Agent}}
	if i := RunsOnMismatch(refs, targets.Agent); i != 1 {
		t.Errorf("agent: %d", i)
	}
	if i := RunsOnMismatch(refs[:1], targets.Agent); i != -1 {
		t.Errorf("ok: %d", i)
	}
}

func TestExpandTemplate(t *testing.T) {
	v := Vars{CertName: "a.example", CertFingerprint: "ff", CertNotAfter: "2027-01-01", GrantID: "g1"}
	got := ExpandTemplate("{{cert.name}}|{{cert.fingerprint}}|{{cert.notAfter}}|{{grant.id}}|{{cert.other}}|{{ cert.name }}|{{.X}}", v)
	want := "a.example|ff|2027-01-01|g1|{{cert.other}}|{{ cert.name }}|{{.X}}"
	if got != want {
		t.Errorf("got %q", got)
	}
	if got := ExpandTemplate("{{cert.name}}", Vars{CertName: "{{grant.id}}", GrantID: "g"}); got != "{{grant.id}}" {
		t.Errorf("rescanned: %q", got)
	}
}
