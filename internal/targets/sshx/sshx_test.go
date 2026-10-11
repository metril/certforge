package sshx

import (
	"context"
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/metril/certforge/internal/targets/sshx/sshxtest"
)

func newSigner(t *testing.T) (ssh.Signer, ed25519.PrivateKey)      { return sshxtest.NewSigner(t) }
func startServer(t *testing.T, pub ssh.PublicKey) *sshxtest.Server { return sshxtest.Start(t, pub) }
func hostLine(s *sshxtest.Server) string                           { return s.HostLine() }
func portOf(t *testing.T, s *sshxtest.Server) int                  { return s.Port(t) }

func dial(t *testing.T, s *sshxtest.Server, o Opts) *Client {
	t.Helper()
	o.Host, o.Port, o.User, o.HostKey, o.AllowLoopback = "127.0.0.1", portOf(t, s), "u", hostLine(s), true
	c, err := Dial(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestHostKeyMismatch(t *testing.T) {
	s := startServer(t, nil)
	other, _ := newSigner(t)
	_, err := Dial(context.Background(), Opts{Host: "127.0.0.1", Port: portOf(t, s), User: "u", Password: "pw",
		HostKey: string(ssh.MarshalAuthorizedKey(other.PublicKey())), AllowLoopback: true})
	if err == nil {
		t.Fatal("want host key mismatch")
	}
}

func TestHostKeyRequired(t *testing.T) {
	if _, err := Dial(context.Background(), Opts{Host: "127.0.0.1", Port: 1, User: "u", Password: "pw", AllowLoopback: true}); err == nil {
		t.Fatal("want error")
	}
}

func TestLoopbackBlocked(t *testing.T) {
	s := startServer(t, nil)
	_, err := Dial(context.Background(), Opts{Host: "127.0.0.1", Port: portOf(t, s), User: "u", Password: "pw", HostKey: hostLine(s)})
	if err == nil {
		t.Fatal("want dial refused")
	}
}

func TestPasswordAuthAndRun(t *testing.T) {
	s := startServer(t, nil)
	c := dial(t, s, Opts{Password: "pw"})
	out, errb, code, err := c.Run(context.Background(), "echo hi")
	if err != nil || code != 0 || string(out) != "out" || string(errb) != "err" {
		t.Fatalf("got %q %q %d %v", out, errb, code, err)
	}
}

func TestBadPassword(t *testing.T) {
	s := startServer(t, nil)
	_, err := Dial(context.Background(), Opts{Host: "127.0.0.1", Port: portOf(t, s), User: "u", Password: "no", HostKey: hostLine(s), AllowLoopback: true})
	if err == nil {
		t.Fatal("want auth error")
	}
}

func TestKeyAuth(t *testing.T) {
	cs, priv := newSigner(t)
	s := startServer(t, cs.PublicKey())
	blk, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	c := dial(t, s, Opts{PrivateKeyPEM: string(pem.EncodeToMemory(blk))})
	if _, _, code, err := c.Run(context.Background(), "true"); err != nil || code != 0 {
		t.Fatal(code, err)
	}
}

func TestWriteFile(t *testing.T) {
	s := startServer(t, nil)
	c := dial(t, s, Opts{Password: "pw"})
	if err := c.WriteFile(context.Background(), "/etc/it's.pem", []byte("DATA"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := `umask 077; rm -f -- '/etc/it'\''s.pem.tmp-certforge'; set -e; cat > '/etc/it'\''s.pem.tmp-certforge' && chmod 0600 -- '/etc/it'\''s.pem.tmp-certforge' && mv -f -- '/etc/it'\''s.pem.tmp-certforge' '/etc/it'\''s.pem'`
	if s.Cmds[0] != want || string(s.Stdin[0]) != "DATA" {
		t.Fatalf("cmd %q stdin %q", s.Cmds[0], s.Stdin[0])
	}
}

func TestNonZeroExit(t *testing.T) {
	s := startServer(t, nil)
	s.Exit = 3
	c := dial(t, s, Opts{Password: "pw"})
	_, _, code, err := c.Run(context.Background(), "false")
	if err != nil || code != 3 {
		t.Fatal(code, err)
	}
	if err := c.WriteFile(context.Background(), "/x", nil, os.FileMode(0o644)); err == nil || !strings.Contains(err.Error(), "exit 3") {
		t.Fatal(err)
	}
}

func TestRunContextTimeout(t *testing.T) {
	s := startServer(t, nil)
	s.Hang = true
	c := dial(t, s, Opts{Password: "pw"})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, _, _, err := c.Run(ctx, "sleep 99"); err == nil {
		t.Fatal("want ctx error")
	}
}

func TestHostKeyMarkerRejected(t *testing.T) {
	s := startServer(t, nil)
	for _, m := range []string{"@revoked", "@cert-authority"} {
		line := m + " 127.0.0.1 " + hostLine(s)
		_, err := Dial(context.Background(), Opts{Host: "127.0.0.1", Port: portOf(t, s), User: "u", Password: "pw", HostKey: line, AllowLoopback: true})
		if err == nil || !strings.Contains(err.Error(), "marker") {
			t.Fatalf("%s: got %v", m, err)
		}
	}
}

func TestWriteFilePathValidation(t *testing.T) {
	s := startServer(t, nil)
	c := dial(t, s, Opts{Password: "pw"})
	for _, p := range []string{"", "rel/x.pem"} {
		if err := c.WriteFile(context.Background(), p, []byte("x"), 0o600); err == nil {
			t.Fatalf("path %q accepted", p)
		}
	}
	if len(s.Cmds) != 0 {
		t.Fatal("command sent for invalid path")
	}
}

func TestWriteFileSCP(t *testing.T) {
	s := startServer(t, nil)
	c := dial(t, s, Opts{Password: "pw"})
	data := []byte("line1\nline2\n\x00bin")
	if err := c.WriteFileSCP(context.Background(), "cf-1.crt", data, 0o644); err != nil {
		t.Fatal(err)
	}
	s.Mu.Lock()
	defer s.Mu.Unlock()
	if string(s.Files["cf-1.crt"]) != string(data) || len(s.Cmds) != 1 || s.Cmds[0] != "scp -t cf-1.crt" {
		t.Fatalf("files=%q cmds=%q", s.Files, s.Cmds)
	}
}

func TestWriteFileSCPRemoteError(t *testing.T) {
	s := startServer(t, nil)
	s.ScpErr = "disk full"
	c := dial(t, s, Opts{Password: "pw"})
	err := c.WriteFileSCP(context.Background(), "a.crt", []byte("x"), 0o644)
	if err == nil || !strings.Contains(err.Error(), "disk full") {
		t.Fatalf("err = %v", err)
	}
	for _, n := range []string{"../a", "a b", "it's", ""} {
		if err := c.WriteFileSCP(context.Background(), n, nil, 0o644); err == nil {
			t.Fatalf("want bad name error for %q", n)
		}
	}
}
