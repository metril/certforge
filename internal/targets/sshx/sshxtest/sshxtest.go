// Package sshxtest is an in-process SSH server for tests: it accepts exec
// requests, records each command with its stdin, and replies with a
// configurable exit status.
package sshxtest

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Server is a running test server. Cmds and Stdin are appended per exec;
// read them with Commands once the client is done.
type Server struct {
	Addr    string
	HostPub ssh.PublicKey
	Mu      sync.Mutex
	Cmds    []string
	Stdin   [][]byte
	// Exit is the default exit status; ExitFor, when set, overrides it per
	// command.
	Exit    uint32
	ExitFor func(cmd string) uint32
	// Hang makes exec requests never complete.
	Hang bool
	// Files holds files uploaded through "scp -t" (name -> data). ScpErr,
	// when set, is sent as a fatal SCP error reply instead of accepting.
	Files map[string][]byte
	// Pass is the accepted password; empty means "pw".
	Pass   string
	ScpErr string
}

// NewSigner returns a fresh ed25519 signer and its private key.
func NewSigner(t *testing.T) (ssh.Signer, ed25519.PrivateKey) {
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

// Start runs a server accepting password "pw" and clientPub (if non-nil).
func Start(t *testing.T, clientPub ssh.PublicKey) *Server {
	t.Helper()
	hs, _ := NewSigner(t)
	s := &Server{HostPub: hs.PublicKey()}
	cfg := &ssh.ServerConfig{
		PasswordCallback: func(_ ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
			want := s.Pass
			if want == "" {
				want = "pw"
			}
			if string(p) == want {
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
	// A second, client-preferred key type: pinning ed25519 must still work.
	ek, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	es, err := ssh.NewSignerFromKey(ek)
	if err != nil {
		t.Fatal(err)
	}
	cfg.AddHostKey(es)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	s.Addr = l.Addr().String()
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

func (s *Server) serve(nc net.Conn, cfg *ssh.ServerConfig) {
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
				if s.Hang {
					continue
				}
				if strings.HasPrefix(cmd, "scp -t ") {
					s.scpSink(ch, cmd)
					continue
				}
				in, _ := io.ReadAll(ch)
				s.Mu.Lock()
				s.Cmds = append(s.Cmds, cmd)
				s.Stdin = append(s.Stdin, in)
				code := s.Exit
				if s.ExitFor != nil {
					code = s.ExitFor(cmd)
				}
				s.Mu.Unlock()
				_, _ = ch.Write([]byte("out"))
				_, _ = ch.Stderr().Write([]byte("err"))
				_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{code}))
				_ = ch.Close()
			}
		}()
	}
}

// HostLine is the server's pinned host key as an authorized_keys line.
func (s *Server) HostLine() string { return string(ssh.MarshalAuthorizedKey(s.HostPub)) }

// Port is the listening port.
func (s *Server) Port(t *testing.T) int {
	t.Helper()
	_, p, _ := net.SplitHostPort(s.Addr)
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// scpSink speaks the receiving side of the SCP protocol and records the
// uploaded file in s.Files.
func (s *Server) scpSink(ch ssh.Channel, cmd string) {
	code := uint32(0)
	defer func() {
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{code}))
		_ = ch.Close()
	}()
	s.Mu.Lock()
	s.Cmds = append(s.Cmds, cmd)
	s.Stdin = append(s.Stdin, nil)
	fail := s.ScpErr
	s.Mu.Unlock()
	if fail != "" {
		_, _ = ch.Write([]byte("\x02" + fail + "\n"))
		code = 1
		return
	}
	_, _ = ch.Write([]byte{0})
	br := bufio.NewReader(ch)
	line, err := br.ReadString('\n')
	if err != nil {
		code = 1
		return
	}
	var mode string
	var n int
	var name string
	if _, err := fmt.Sscanf(line, "C%s %d %s", &mode, &n, &name); err != nil {
		code = 1
		return
	}
	_, _ = ch.Write([]byte{0})
	data := make([]byte, n)
	if _, err := io.ReadFull(br, data); err != nil {
		code = 1
		return
	}
	if b, err := br.ReadByte(); err != nil || b != 0 {
		code = 1
		return
	}
	s.Mu.Lock()
	if s.Files == nil {
		s.Files = map[string][]byte{}
	}
	s.Files[name] = data
	s.Mu.Unlock()
	_, _ = ch.Write([]byte{0})
	_, _ = io.Copy(io.Discard, br)
}
