package sshx

import (
	"context"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/targets/sshx/sshxtest"
)

func TestScanHostKeys(t *testing.T) {
	srv := sshxtest.Start(t, nil)
	keys, err := ScanHostKeys(context.Background(), "127.0.0.1", srv.Port(t), true)
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, k := range keys {
		if k.Type == "ssh-ed25519" {
			found = k.Line == strings.TrimSpace(srv.HostLine()) && strings.HasPrefix(k.Sha256, "SHA256:")
		}
	}
	if !found {
		t.Fatalf("ed25519 key missing or wrong: %+v", keys)
	}
	if _, err := ScanHostKeys(context.Background(), "127.0.0.1", 1, true); err == nil {
		t.Fatal("closed port: want error")
	}
}
