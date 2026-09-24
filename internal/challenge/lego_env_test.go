package challenge

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
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

// mustBase64PEMKey generates a throwaway unencrypted RSA key and returns
// base64(PEM(key)) — the exact form oraclecloud's OCI_PRIVKEY needs
// (configprovider.go's getPrivateKey base64-decodes the env value, then
// PrivateKeyFromBytesWithPassword PEM-decodes the result).
func mustBase64PEMKey(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return base64.StdEncoding.EncodeToString(pem.EncodeToMemory(block))
}

// Review Focus (fix round 3): oraclecloud's OCI_PRIVKEY must be base64 of
// the whole PEM file, not the PEM text itself (configprovider.go's
// getPrivateKey base64-decodes the raw env value before PEM-decoding it) —
// the schema description said otherwise until this fix. Dummy OCID/region/
// fingerprint values mirror lego's own "success" test case for this
// provider (oraclecloud_test.go), which the OCI SDK client accepts without
// any network call at construction time.
func TestBuildOracleCloudSucceedsWithBase64PEMKey(t *testing.T) {
	cfg := map[string]string{
		"OCI_PRIVKEY":            mustBase64PEMKey(t),
		"OCI_TENANCY_OCID":       "ocid1.tenancy.oc1..secret",
		"OCI_USER_OCID":          "ocid1.user.oc1..secret",
		"OCI_PUBKEY_FINGERPRINT": "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
		"OCI_REGION":             "us-phoenix-1",
		"OCI_COMPARTMENT_OCID":   "123",
	}
	p, err := Build("oraclecloud", cfg)
	if err != nil {
		t.Fatalf("want success with a base64-encoded PEM key, got: %v", err)
	}
	if p == nil {
		t.Fatal("want a non-nil provider")
	}
}

// Review Focus (fix round 3): a raw (non-base64) PEM in OCI_PRIVKEY must
// fail construction (lego's own error echoes the raw env value: "failed to
// read base64 value %s ..."), and that failure must not leak the key
// through Build's Scrub'd error.
func TestBuildOracleCloudRejectsRawPEMWithScrubbedError(t *testing.T) {
	rawPEM := "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD91assbzO39gyMDL7O+8/HG1V8b\n-----END RSA PRIVATE KEY-----"
	cfg := map[string]string{
		"OCI_PRIVKEY":            rawPEM,
		"OCI_TENANCY_OCID":       "ocid1.tenancy.oc1..secret",
		"OCI_USER_OCID":          "ocid1.user.oc1..secret",
		"OCI_PUBKEY_FINGERPRINT": "00:00:00:00:00:00:00:00:00:00:00:00:00:00:00:00",
		"OCI_REGION":             "us-phoenix-1",
		"OCI_COMPARTMENT_OCID":   "123",
	}
	_, err := Build("oraclecloud", cfg)
	if err == nil {
		t.Fatal("want an error: a raw (non-base64) PEM must fail to decode")
	}
	if strings.Contains(err.Error(), rawPEM) || strings.Contains(err.Error(), "MIIBOgIBAAJBAKj34GkxFhD91assbzO39gyMDL7O+8/HG1V8b") {
		t.Fatalf("raw key leaked through the error: %s", err.Error())
	}
	if !strings.Contains(err.Error(), redacted) {
		t.Fatalf("expected the redaction marker in the error: %s", err.Error())
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
