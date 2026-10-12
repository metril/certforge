package deploy

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/metril/certforge/internal/render"
	"github.com/metril/certforge/internal/targets"
	"github.com/metril/certforge/internal/targets/sshx/sshxtest"
)

func sshCfg(t *testing.T, s *sshxtest.Server, mut func(map[string]any)) json.RawMessage {
	t.Helper()
	m := map[string]any{
		"host": "127.0.0.1", "port": s.Port(t), "username": "root", "password": "pw",
		"hostKey": s.HostLine(), "timeoutSeconds": 10,
		"files": []map[string]any{
			{"path": "/etc/kvmd/user/ssl/server.crt", "content": "fullchain", "mode": "0644"},
			{"path": "/etc/kvmd/user/ssl/server.key", "content": "key", "mode": "0600"},
		},
		"preCommand": "rw", "postCommand": "ro; systemctl restart kvmd-nginx",
	}
	if mut != nil {
		mut(m)
	}
	b, _ := json.Marshal(m)
	return b
}

func sshReq(cfg json.RawMessage, m *render.Material, files ...render.File) targets.Request {
	return targets.Request{CertName: "web", Material: m, Files: files, Config: cfg, HTTP: targets.HTTPFactory{AllowLoopback: true}}
}

func TestSSHOrdering(t *testing.T) {
	s := sshxtest.Start(t, nil)
	m, _ := akMaterial(t)
	res, err := SSH{}.Deploy(context.Background(), sshReq(sshCfg(t, s, nil), m))
	if err != nil {
		t.Fatal(err)
	}
	if res.Detail != "2 files written; post: ok" {
		t.Fatalf("detail = %q", res.Detail)
	}
	if len(s.Cmds) != 4 || s.Cmds[0] != "rw" || s.Cmds[3] != "ro; systemctl restart kvmd-nginx" {
		t.Fatalf("cmds = %q", s.Cmds)
	}
	if !strings.Contains(s.Cmds[1], "server.crt") || !strings.Contains(s.Cmds[2], "server.key") || !strings.Contains(s.Cmds[2], "chmod 0600") {
		t.Fatalf("cmds = %q", s.Cmds)
	}
	if !strings.Contains(string(s.Stdin[1]), "BEGIN CERTIFICATE") || !strings.Contains(string(s.Stdin[2]), "PRIVATE KEY") {
		t.Fatal("file contents wrong")
	}
}

func TestSSHPostRunsAfterWriteFailure(t *testing.T) {
	s := sshxtest.Start(t, nil)
	s.ExitFor = func(cmd string) uint32 {
		if strings.Contains(cmd, "server.crt") {
			return 1
		}
		return 0
	}
	m, _ := akMaterial(t)
	_, err := SSH{}.Deploy(context.Background(), sshReq(sshCfg(t, s, nil), m))
	if err == nil || !strings.Contains(err.Error(), "server.crt") {
		t.Fatalf("err = %v", err)
	}
	if last := s.Cmds[len(s.Cmds)-1]; last != "ro; systemctl restart kvmd-nginx" {
		t.Fatalf("post did not run last: %q", s.Cmds)
	}
	if len(s.Cmds) != 3 {
		t.Fatalf("key file written after failure: %q", s.Cmds)
	}
}

func TestSSHPreFailureSkipsFiles(t *testing.T) {
	s := sshxtest.Start(t, nil)
	s.ExitFor = func(cmd string) uint32 {
		if cmd == "rw" {
			return 2
		}
		return 0
	}
	m, _ := akMaterial(t)
	_, err := SSH{}.Deploy(context.Background(), sshReq(sshCfg(t, s, nil), m))
	if err == nil || !strings.Contains(err.Error(), "preCommand") {
		t.Fatalf("err = %v", err)
	}
	if len(s.Cmds) != 1 {
		t.Fatalf("cmds = %q", s.Cmds)
	}
}

func TestSSHHostKeyMismatch(t *testing.T) {
	s := sshxtest.Start(t, nil)
	other, _ := sshxtest.NewSigner(t)
	m, _ := akMaterial(t)
	cfg := sshCfg(t, s, func(c map[string]any) { c["hostKey"] = string(ssh.MarshalAuthorizedKey(other.PublicKey())) })
	if _, err := (SSH{}).Deploy(context.Background(), sshReq(cfg, m)); err == nil {
		t.Fatal("want error")
	}
	if len(s.Cmds) != 0 {
		t.Fatalf("commands ran: %q", s.Cmds)
	}
}

func TestSSHNoKeyMaterialUnlessRequested(t *testing.T) {
	s := sshxtest.Start(t, nil)
	m, _ := akMaterial(t)
	cfg := sshCfg(t, s, func(c map[string]any) {
		c["files"] = []map[string]any{{"path": "/tmp/c.pem", "content": "fullchain"}}
		delete(c, "preCommand")
		delete(c, "postCommand")
	})
	res, err := SSH{}.Deploy(context.Background(), sshReq(cfg, m))
	if err != nil || res.Detail != "1 files written" {
		t.Fatal(res, err)
	}
	for _, in := range s.Stdin {
		if strings.Contains(string(in), "PRIVATE KEY") {
			t.Fatal("key sent")
		}
	}
}

func TestSSHBundleAndLayoutFile(t *testing.T) {
	s := sshxtest.Start(t, nil)
	m, _ := akMaterial(t)
	cfg := sshCfg(t, s, func(c map[string]any) {
		c["files"] = []map[string]any{
			{"path": "/etc/b.pem", "content": "bundle", "mode": "0600"},
			{"path": "/etc/x.p12", "content": "cert.p12"},
		}
		delete(c, "preCommand")
		delete(c, "postCommand")
	})
	req := sshReq(cfg, m, render.File{Name: "cert.p12", Data: []byte("P12DATA"), Secret: true})
	if _, err := (SSH{}).Deploy(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	in := string(s.Stdin[0])
	if !strings.Contains(in, "BEGIN CERTIFICATE") || !strings.Contains(in, "PRIVATE KEY") || strings.Index(in, "BEGIN CERTIFICATE") > strings.Index(in, "PRIVATE KEY") {
		t.Fatalf("bundle = %q", in)
	}
	if string(s.Stdin[1]) != "P12DATA" {
		t.Fatalf("layout file = %q", s.Stdin[1])
	}
}

func TestSSHUnknownContent(t *testing.T) {
	s := sshxtest.Start(t, nil)
	m, _ := akMaterial(t)
	cfg := sshCfg(t, s, func(c map[string]any) {
		c["files"] = []map[string]any{{"path": "/etc/n.pem", "content": "nope.pem"}}
	})
	_, err := SSH{}.Deploy(context.Background(), sshReq(cfg, m))
	if err == nil || !strings.Contains(err.Error(), "nope.pem") {
		t.Fatalf("err = %v", err)
	}
	if len(s.Cmds) != 0 {
		t.Fatalf("commands ran before validation: %q", s.Cmds)
	}
}

func TestSSHParse(t *testing.T) {
	s := sshxtest.Start(t, nil)
	if c, err := (SSH{}).Parse(sshCfg(t, s, nil)); err != nil || !c.NeedsKey || len(c.URLs) != 1 || !strings.HasPrefix(c.URLs[0], "ssh://127.0.0.1:") {
		t.Fatalf("%+v %v", c, err)
	} else if _, ok := c.Secrets["password"]; !ok {
		t.Fatalf("password not split: %+v", c)
	}
	c, err := SSH{}.Parse(sshCfg(t, s, func(c map[string]any) {
		c["files"] = []map[string]any{{"path": "/a", "content": "cert"}}
	}))
	if err != nil || c.NeedsKey {
		t.Fatalf("NeedsKey = %v err %v", c.NeedsKey, err)
	}
	bad := map[string]func(map[string]any){
		"no auth":     func(c map[string]any) { delete(c, "password") },
		"no host":     func(c map[string]any) { delete(c, "host") },
		"no user":     func(c map[string]any) { delete(c, "username") },
		"bad hostKey": func(c map[string]any) { c["hostKey"] = "garbage" },
		"no hostKey":  func(c map[string]any) { delete(c, "hostKey") },
		"rel path":    func(c map[string]any) { c["files"] = []map[string]any{{"path": "etc/a", "content": "cert"}} },
		"bad mode": func(c map[string]any) {
			c["files"] = []map[string]any{{"path": "/a", "content": "cert", "mode": "644"}}
		},
		"bad content":  func(c map[string]any) { c["files"] = []map[string]any{{"path": "/a", "content": "a b"}} },
		"no files":     func(c map[string]any) { c["files"] = []map[string]any{} },
		"bad port":     func(c map[string]any) { c["port"] = 70000 },
		"bad timeout":  func(c map[string]any) { c["timeoutSeconds"] = 1 },
		"long command": func(c map[string]any) { c["preCommand"] = strings.Repeat("x", 513) },
		"unknown":      func(c map[string]any) { c["extra"] = 1 },
	}
	for name, mut := range bad {
		if _, err := (SSH{}).Parse(sshCfg(t, s, mut)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

type fakeRecorder struct{ runs []targets.HookRun }

func (f *fakeRecorder) RecordHook(_ context.Context, r targets.HookRun) { f.runs = append(f.runs, r) }

func TestSSHRecordsCommands(t *testing.T) {
	s := sshxtest.Start(t, nil)
	s.ExitFor = func(cmd string) uint32 {
		if cmd == "rw" {
			return 0
		}
		if strings.HasPrefix(cmd, "ro") {
			return 4
		}
		return 0
	}
	m, _ := akMaterial(t)
	rec := &fakeRecorder{}
	req := sshReq(sshCfg(t, s, nil), m)
	req.Recorder = rec
	if _, err := (SSH{}).Deploy(context.Background(), req); err == nil {
		t.Fatal("post command exit 4 should fail")
	}
	if len(rec.runs) != 2 {
		t.Fatalf("runs = %+v", rec.runs)
	}
	pre, post := rec.runs[0], rec.runs[1]
	if pre.Phase != "pre_deploy" || pre.ExitCode != 0 || strings.Join(pre.Argv, "|") != "ssh|127.0.0.1|rw" {
		t.Fatalf("pre = %+v", pre)
	}
	if post.Phase != "post_deploy" || post.ExitCode != 4 || post.Argv[2] != "ro; systemctl restart kvmd-nginx" {
		t.Fatalf("post = %+v", post)
	}
}

// TestCredentialKinds: every server target's credentialKinds names known
// credential kinds, and the keywords are the ones the design assigns.
func TestCredentialKinds(t *testing.T) {
	want := map[string][]string{
		"ssh": {"ssh", "password"}, "pfsense": {"password"}, "routeros": {"password"},
		"truenas": {"apiKey"}, "authentik": {"token"},
	}
	known := map[string]bool{}
	for _, k := range targets.Kinds() {
		known[k] = true
	}
	for typ, kinds := range want {
		var tg targets.Target
		switch typ {
		case "ssh":
			tg = SSH{}
		case "pfsense":
			tg = PfSense{}
		case "routeros":
			tg = RouterOS{}
		case "truenas":
			tg = TrueNAS{}
		case "authentik":
			tg = Authentik{}
		}
		got := targets.AcceptedKinds(tg.Schema())
		if !reflect.DeepEqual(got, kinds) {
			t.Errorf("%s credentialKinds = %v, want %v", typ, got, kinds)
		}
		for _, k := range got {
			if !known[k] {
				t.Errorf("%s: unknown kind %q", typ, k)
			}
		}
	}
}
