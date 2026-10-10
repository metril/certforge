package agentproto

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMarshalRoundTrip(t *testing.T) {
	id := uuid.New()
	for _, m := range []Message{
		Hello{AgentVersion: "1.0.0", Hostname: "web-1", OS: "linux", Arch: "amd64", Capabilities: []string{"traefik"}},
		Welcome{HeartbeatSeconds: 60, Revision: 3},
		Sync{Revision: 4},
		TrustBundleUpdate{Bundle: "-----BEGIN CERTIFICATE-----\n"},
		Revoked{},
		Heartbeat{Installed: []InstalledFile{{GrantID: id, Path: "/etc/x.pem", SHA256: "ab", MTime: time.Unix(1700000000, 0).UTC()}}},
		DeployResult{Report: Report{Revision: 5, Results: []GrantResult{{GrantID: id, VersionID: id, State: StateOK}}}},
	} {
		b, err := Marshal(m)
		if err != nil {
			t.Fatalf("%s: %v", m.MsgType(), err)
		}
		got, err := Unmarshal(b)
		if err != nil {
			t.Fatalf("%s: %v (%s)", m.MsgType(), err, b)
		}
		if !reflect.DeepEqual(got, m) {
			t.Fatalf("%s: %#v != %#v", m.MsgType(), got, m)
		}
	}
}

func TestMarshalAddsType(t *testing.T) {
	for m, want := range map[Message]string{
		Revoked{}:         `{"type":"revoked"}`,
		Sync{Revision: 1}: `{"type":"sync","revision":1}`,
	} {
		b, err := Marshal(m)
		if err != nil || string(b) != want {
			t.Fatalf("Marshal(%T) = %s %v", m, b, err)
		}
	}
}

func TestUnmarshalUnknownType(t *testing.T) {
	if _, err := Unmarshal([]byte(`{"type":"nonexistent_type"}`)); !errors.Is(err, ErrUnknownType) {
		t.Fatalf("err = %v", err)
	}
	if _, err := Unmarshal([]byte(`not json`)); err == nil {
		t.Fatal("garbage accepted")
	}
}

// TestChallengeMessagesRoundTrip: the agent challenge relay's three
// messages (Task 7) Marshal and Unmarshal with their own "type", the same
// as every other Message.
func TestChallengeMessagesRoundTrip(t *testing.T) {
	for _, m := range []Message{
		ChallengePresent{Token: "tok", KeyAuth: "tok.thumb", Domain: "example.test", Method: "http-01", Webroot: "/var/www/acme"},
		ChallengePresent{Token: "tok2", KeyAuth: "tok2.thumb", Domain: "example.test", Method: "tls-alpn-01"},
		ChallengeCleanup{Token: "tok"},
		ChallengeReady{Token: "tok"},
		ChallengeReady{Token: "tok", Error: "listener not configured"},
	} {
		b, err := Marshal(m)
		if err != nil {
			t.Fatalf("%s: %v", m.MsgType(), err)
		}
		got, err := Unmarshal(b)
		if err != nil {
			t.Fatalf("%s: %v (%s)", m.MsgType(), err, b)
		}
		if !reflect.DeepEqual(got, m) {
			t.Fatalf("%s: %#v != %#v", m.MsgType(), got, m)
		}
	}
}

func TestRenewDue(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(90 * 24 * time.Hour)
	if RenewDue(nb, na, nb.Add(59*24*time.Hour)) {
		t.Fatal("due too early")
	}
	if !RenewDue(nb, na, nb.Add(60*24*time.Hour)) {
		t.Fatal("not due at two thirds")
	}
}
