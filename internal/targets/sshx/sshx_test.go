package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type srv struct {
	addr    string
	hostPub ssh.PublicKey
	mu      sync.Mutex
	cmds    []string
	stdin   [][]byte
	exit    uint32
	hang    bool
}

func newSigner(t *testing.T) (ssh.Signer, ed25519.PrivateKey) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, priv
}

func startServer(t *testing.T, clientPub ssh.PublicKey) *srv {
	t.Helper()
	hs, _ := newSigner(t)
	s := &srv{hostPub: hs.PublicKey()}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			if string(p) == "pw" {
				return nil, nil
			}
			return nil, io.EOF
		},
		PublicKeyCallback: func(_ ssh.ConnMetadata, k ssh.PublicKey) (*ssh.Permissions, error) {
			if clientPub != nil && string(k.Marshal()) == string(clientPub.Marshal()) {
				return nil, nil
			}
			return nil, io.EOF
		},
	}
	cfg.AddHostKey(hs)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	s.addr = l.Addr().String()
	go func() {
		for {
			nc, err := l.Accept()
			if err != nil {
				return
			}
			go s.serve(nc, cfg)
		}
	}()
	return s
}

func (s *srv) serve(nc net.Conn, cfg *ssh.ServerConfig) {
	_, chans, reqs, err := ssh.NewServerConn(nc, cfg)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nch := range chans {
		ch, creqs, err := nch.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range creqs {
				if r.Type != "exec" {
					_ = r.Reply(false, nil)
					continue
				}
				_ = r.Reply(true, nil)
				cmd := string(r.Payload[4:])
				if s.hang {
					continue
				}
				in, _ := io.ReadAll(ch)
				s.mu.Lock()
				s.cmds = append(s.cmds, cmd)
				s.stdin = append(s.stdin, in)
				code := s.exit
				s.mu.Unlock()
				_, _ = ch.Write([]byte("out"))
				_, _ = ch.Stderr().Write([]byte("err"))
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{code}))
				_ = ch.Close()
			}
		}()
	}
}

func hostLine(s *srv) string { return string(ssh.MarshalAuthorizedKey(s.hostPub)) }

func portOf(t *testing.T, s *srv) int {
	t.Helper()
	_, p, _ := net.SplitHostPort(s.addr)
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func dial(t *testing.T, s *srv, o Opts) *Client {
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
	want := `set -e; cat > '/etc/it'\''s.pem.tmp-certforge' && chmod 0600 '/etc/it'\''s.pem.tmp-certforge' && mv -f '/etc/it'\''s.pem.tmp-certforge' '/etc/it'\''s.pem'`
	if s.cmds[0] != want || string(s.stdin[0]) != "DATA" {
		t.Fatalf("cmd %q stdin %q", s.cmds[0], s.stdin[0])
	}
}

func TestNonZeroExit(t *testing.T) {
	s := startServer(t, nil)
	s.exit = 3
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
	s.hang = true
	c := dial(t, s, Opts{Password: "pw"})
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, _, _, err := c.Run(ctx, "sleep 99"); err == nil {
		t.Fatal("want ctx error")
	}
}
