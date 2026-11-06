package deploy

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/targets/sshx/sshxtest"
)

func glkvmCfgT(t *testing.T, s *sshxtest.Server, mut func(map[string]any)) json.RawMessage {
	t.Helper()
	m := map[string]any{"host": "127.0.0.1", "port": s.Port(t), "password": "pw", "hostKey": s.HostLine(), "timeoutSeconds": 10}
	if mut != nil {
		mut(m)
	}
	b, _ := json.Marshal(m)
	return b
}

func TestGLKVMDeployOrder(t *testing.T) {
	s := sshxtest.Start(t, nil)
	m, _ := akMaterial(t)
	cfg := glkvmCfgT(t, s, nil)
	if _, err := (GLKVM{}).Deploy(context.Background(), sshReq(cfg, m)); err != nil {
		t.Fatal(err)
	}
	if len(s.Cmds) != 2 {
		t.Fatalf("cmds = %q", s.Cmds)
	}
	if !strings.Contains(s.Cmds[0], "/etc/kvmd/user/ssl/server.crt") || !strings.Contains(s.Cmds[0], "chmod 0644") ||
		!strings.Contains(s.Cmds[1], "/etc/kvmd/user/ssl/server.key") || !strings.Contains(s.Cmds[1], "chmod 0600") {
		t.Fatalf("cmds = %q", s.Cmds)
	}
	if !strings.Contains(string(s.Stdin[0]), "BEGIN CERTIFICATE") || !strings.Contains(string(s.Stdin[1]), "PRIVATE KEY") {
		t.Fatal("file contents wrong")
	}
}

func TestGLKVMWriteFailure(t *testing.T) {
	s := sshxtest.Start(t, nil)
	s.ExitFor = func(cmd string) uint32 {
		if strings.Contains(cmd, "server.crt") {
			return 1
		}
		return 0
	}
	m, _ := akMaterial(t)
	_, err := GLKVM{}.Deploy(context.Background(), sshReq(glkvmCfgT(t, s, nil), m))
	if err == nil || !strings.Contains(err.Error(), "deploy: glkvm: ") {
		t.Fatalf("err = %v", err)
	}
	if len(s.Cmds) != 1 {
		t.Fatalf("cmds = %q", s.Cmds)
	}
}

func TestGLKVMParse(t *testing.T) {
	s := sshxtest.Start(t, nil)
	c, err := GLKVM{}.Parse(glkvmCfgT(t, s, nil))
	if err != nil {
		t.Fatal(err)
	}
	var pub map[string]any
	_ = json.Unmarshal(c.Public, &pub)
	if pub["username"] != "root" || pub["port"] == nil || !c.NeedsKey || len(c.URLs) != 1 || !strings.HasPrefix(c.URLs[0], "ssh://127.0.0.1:") {
		t.Fatalf("pub = %v, cfg = %+v", pub, c)
	}
	if _, ok := c.Secrets["password"]; !ok {
		t.Fatalf("secrets = %v", c.Secrets)
	}
	_, err = GLKVM{}.Parse(glkvmCfgT(t, s, func(m map[string]any) { m["privateKey"] = "junk" }))
	var fe *delivery.FieldError
	if !errors.As(err, &fe) || fe.Field != "config.privateKey" {
		t.Fatalf("err = %v", err)
	}
}
