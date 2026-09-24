package challenge

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	legochallenge "github.com/go-acme/lego/v4/challenge"
)

type envCapture struct{ token, email, fileVar string }

func (envCapture) Present(string, string, string) error { return nil }
func (envCapture) CleanUp(string, string, string) error { return nil }

// Review Focus: lego env leakage between concurrent issuances.
func TestBuildIsolatesEnvironment(t *testing.T) {
	orig := newByName
	t.Cleanup(func() { newByName = orig })
	newByName = func(code string) (legochallenge.Provider, error) {
		return envCapture{os.Getenv("CF_DNS_API_TOKEN"), os.Getenv("CF_API_EMAIL"), os.Getenv("CF_DNS_API_TOKEN_FILE")}, nil
	}
	t.Setenv("CF_API_EMAIL", "host@example.com")
	t.Setenv("CF_DNS_API_TOKEN_FILE", "/run/secrets/host-token")

	var wg sync.WaitGroup
	errs := make(chan error, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			want := fmt.Sprintf("token-%d", i)
			p, err := Build("cloudflare", map[string]string{"CF_DNS_API_TOKEN": want})
			if err != nil {
				errs <- err
				return
			}
			got := p.(envCapture)
			if got.token != want || got.email != "" || got.fileVar != "" {
				errs <- fmt.Errorf("build %d saw %+v", i, got)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	if os.Getenv("CF_API_EMAIL") != "host@example.com" || os.Getenv("CF_DNS_API_TOKEN_FILE") != "/run/secrets/host-token" {
		t.Fatal("host environment not restored")
	}
	if _, set := os.LookupEnv("CF_DNS_API_TOKEN"); set {
		t.Fatal("credential value leaked into process environment")
	}
}

func TestBuildRejectsUnknownKeys(t *testing.T) {
	if _, err := Build("cloudflare", map[string]string{"PATH": "/evil"}); err == nil {
		t.Fatal("want error")
	}
	if _, err := Build("nope", nil); err == nil {
		t.Fatal("want unknown provider error")
	}
}

// Review Focus: Unchanged is a write-only sentinel for stored credential
// updates; it must never reach a live provider build.
func TestBuildRejectsUnchangedSentinel(t *testing.T) {
	_, err := Build("cloudflare", map[string]string{"CF_DNS_API_TOKEN": Unchanged})
	if err == nil {
		t.Fatal("want error for unresolved sentinel")
	}
	if !strings.Contains(err.Error(), Unchanged) {
		t.Fatalf("error should name the sentinel: %v", err)
	}
}

func TestBuildUsesRegisteredFactory(t *testing.T) {
	called := false
	err := Register(ProviderMeta{Code: "unit-fake", Name: "Unit fake", Schema: []byte(`{"properties":{"URL":{"type":"string"}}}`)},
		func(cfg map[string]string) (legochallenge.Provider, error) {
			called = cfg["URL"] == "http://x"
			return envCapture{}, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Build("unit-fake", map[string]string{"URL": "http://x"}); err != nil || !called {
		t.Fatalf("factory not used: %v", err)
	}
}
