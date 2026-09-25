package agents

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/metril/certforge/internal/settings"
)

func TestResolveDefaults(t *testing.T) {
	s := Resolve(Settings{}, "https://cf.example.com")
	if s.AgentURL != "https://cf.example.com:8443" || !slices.Equal(s.ListenerNames, []string{"cf.example.com", "localhost"}) ||
		s.TokenTTLHours != 24 || s.AgentCertDays != 90 || s.HeartbeatSeconds != 60 || s.OfflineAfterSeconds != 180 {
		t.Fatalf("resolved %+v", s)
	}
	if got := Resolve(Settings{}, "").AgentURL; got != "https://localhost:8443" {
		t.Fatalf("no base URL: %s", got)
	}
	if s.TokenTTL() != 24*time.Hour || s.AgentCertLifetime() != 90*24*time.Hour {
		t.Fatal("durations")
	}
}

func TestNamesIncludeAgentURLHost(t *testing.T) {
	s := Resolve(Settings{AgentURL: "https://Agents.Example.com:9443/", ListenerNames: []string{"cf.lan", "10.0.0.5", "cf.lan"}}, "")
	if s.AgentURL != "https://Agents.Example.com:9443" {
		t.Fatalf("agentUrl %s", s.AgentURL)
	}
	if got := s.Names(); !slices.Equal(got, []string{"cf.lan", "10.0.0.5", "agents.example.com"}) {
		t.Fatalf("names %v", got)
	}
}

func TestSettingsSectionValidates(t *testing.T) {
	r := settings.NewRegistry()
	if err := RegisterSettings(r); err != nil {
		t.Fatal(err)
	}
	sec, _ := r.Section(SettingsSection)
	if err := sec.Validate([]byte(settingsDefault)); err != nil {
		t.Fatalf("default invalid: %v", err)
	}
	for name, raw := range map[string]string{
		"http url":      `{"agentUrl":"http://cf.example.com:8443"}`,
		"url path":      `{"agentUrl":"https://cf.example.com:8443/agent"}`,
		"bad name":      `{"listenerNames":["not a name"]}`,
		"heartbeat low": `{"heartbeatSeconds":10}`,
		"offline <= hb": `{"heartbeatSeconds":60,"offlineAfterSeconds":60}`,
		"unknown":       `{"nope":1}`,
	} {
		if err := sec.Validate([]byte(raw)); !errors.Is(err, settings.ErrInvalid) {
			t.Errorf("%s: err = %v", name, err)
		}
	}
}

func TestSettingsSourceCachesAndInvalidates(t *testing.T) {
	calls := 0
	src := &SettingsSource{baseURL: "https://cf.example.com", ttl: time.Minute, now: time.Now,
		load: func(context.Context) (Settings, error) {
			calls++
			return Settings{HeartbeatSeconds: 30 * calls}, nil
		}}
	a, _ := src.Get(context.Background())
	b, _ := src.Get(context.Background())
	if calls != 1 || a.HeartbeatSeconds != 30 || b.HeartbeatSeconds != 30 || a.AgentURL != "https://cf.example.com:8443" {
		t.Fatalf("calls %d a %+v", calls, a)
	}
	src.Invalidate()
	c, _ := src.Get(context.Background())
	if calls != 2 || c.HeartbeatSeconds != 60 {
		t.Fatalf("after invalidate calls %d %+v", calls, c)
	}
	st := StaticSettings(Settings{HeartbeatSeconds: 1}, "https://x.test")
	if got, _ := st.Get(context.Background()); got.HeartbeatSeconds != 1 || got.AgentURL != "https://x.test:8443" {
		t.Fatalf("static %+v", got)
	}
	var js map[string]any
	if err := json.Unmarshal([]byte(settingsSchema), &js); err != nil {
		t.Fatal(err)
	}
}
