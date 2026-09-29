package challenge

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	legochallenge "github.com/go-acme/lego/v4/challenge"
)

// Review Focus: a file-backed credential's private temp directory must be
// gone once Build returns, whether the provider construction that reads it
// succeeds or fails, and the file itself must exist at 0600 while the
// provider is being built. This uses a registered factory stub (not a real
// lego provider) so the test controls exactly when the path is observed.
func TestFileBackedTempLifecycle(t *testing.T) {
	const code = "unit-filebacked"
	fileBacked[code] = map[string]string{"UNIT_INLINE_CRED": "UNIT_INLINE_CRED_PATH"}
	t.Cleanup(func() { delete(fileBacked, code) })

	schema := []byte(`{"properties":{"UNIT_INLINE_CRED":{"type":"string","secret":true}}}`)

	var gotPath, gotDir string
	registerFactory := func(f Factory) {
		if err := Register(ProviderMeta{Code: code, Name: "Unit filebacked", Schema: schema}, f); err != nil {
			t.Fatal(err)
		}
	}

	// Success path.
	registerFactory(func(cfg map[string]string) (legochallenge.Provider, error) {
		if _, ok := cfg["UNIT_INLINE_CRED"]; ok {
			t.Fatal("inline key must not reach the factory")
		}
		gotPath = cfg["UNIT_INLINE_CRED_PATH"]
		if gotPath == "" {
			t.Fatal("path env key not set in the isolated cfg")
		}
		fi, err := os.Stat(gotPath)
		if err != nil {
			t.Fatalf("temp file missing at construction: %v", err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("temp file mode = %v, want 0600", fi.Mode().Perm())
		}
		gotDir = filepath.Dir(gotPath)
		return envCapture{}, nil
	})
	if _, err := Build(code, map[string]string{"UNIT_INLINE_CRED": "secret-material"}); err != nil {
		t.Fatal(err)
	}
	if gotDir == "" {
		t.Fatal("factory never observed the path")
	}
	if _, err := os.Stat(gotDir); !os.IsNotExist(err) {
		t.Fatalf("temp dir not removed after success: %v", err)
	}

	// Error path: the dir must still be removed.
	gotDir = ""
	registerFactory(func(cfg map[string]string) (legochallenge.Provider, error) {
		gotDir = filepath.Dir(cfg["UNIT_INLINE_CRED_PATH"])
		return nil, fmt.Errorf("boom")
	})
	if _, err := Build(code, map[string]string{"UNIT_INLINE_CRED": "secret-material"}); err == nil {
		t.Fatal("want error")
	}
	if gotDir == "" {
		t.Fatal("factory never observed the path")
	}
	if _, err := os.Stat(gotDir); !os.IsNotExist(err) {
		t.Fatalf("temp dir not removed after error: %v", err)
	}
}

// Review Focus (batch-5 review): a file-backed provider's own construction
// error can quote its temp file path verbatim (hyperone's open error does
// exactly this) — Build must scrub buildCfg's own values too, not only
// cfg's (the inline credential was never written into cfg's path-keyed
// form, so scrubbing cfg alone never touches this path at all).
func TestBuildScrubsFileBackedTempPath(t *testing.T) {
	const code = "unit-filebacked-scrub"
	fileBacked[code] = map[string]string{"UNIT_INLINE_CRED": "UNIT_INLINE_CRED_PATH"}
	t.Cleanup(func() { delete(fileBacked, code) })

	schema := []byte(`{"properties":{"UNIT_INLINE_CRED":{"type":"string","secret":true}}}`)
	var gotPath string
	if err := Register(ProviderMeta{Code: code, Name: "Unit filebacked scrub", Schema: schema},
		func(cfg map[string]string) (legochallenge.Provider, error) {
			gotPath = cfg["UNIT_INLINE_CRED_PATH"]
			return nil, fmt.Errorf("open %s: permission denied", gotPath)
		}); err != nil {
		t.Fatal(err)
	}

	_, err := Build(code, map[string]string{"UNIT_INLINE_CRED": "secret-material"})
	if err == nil {
		t.Fatal("want error")
	}
	if gotPath == "" {
		t.Fatal("factory never observed the path")
	}
	if strings.Contains(err.Error(), gotPath) {
		t.Fatalf("temp path %q leaked through the error: %v", gotPath, err)
	}
	if !strings.Contains(err.Error(), redacted) {
		t.Fatalf("expected the redaction marker in the error: %v", err)
	}
}

// mustRSAKeyPEM generates a throwaway unencrypted RSA key and PEM-encodes
// it, the form TRANSIP_PRIVATE_KEY holds inline.
func mustRSAKeyPEM(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	block := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}
	return string(pem.EncodeToMemory(block))
}

// Review Focus: transip's NewDNSProviderConfig reads TRANSIP_PRIVATE_KEY_PATH
// eagerly via gotransip.NewClient (io.ReadAll on the opened file) with no
// network call, so construction from an inline key must succeed with the
// temp file gone afterward, proving Build's file-backed wiring end to end
// against the real lego provider (not a stub).
func TestTransipBuildsFromInlineKey(t *testing.T) {
	p, err := Build("transip", map[string]string{
		"TRANSIP_ACCOUNT_NAME": "unit-account",
		"TRANSIP_PRIVATE_KEY":  mustRSAKeyPEM(t),
	})
	if err != nil {
		t.Fatalf("want success building transip from an inline key, got: %v", err)
	}
	if p == nil {
		t.Fatal("want a non-nil provider")
	}
}

// hyperonePassportJSON is a syntactically valid HyperOne passport: the
// fields internal.LoadPassportFile's validate() requires, plus a
// subject_id internal.ExtractProjectID's regex accepts. No network call is
// made at construction (internal.NewClient only parses the passport and
// builds a token signer).
const hyperonePassportJSON = `{
  "subject_id": "/iam/project/unitproject/sa/unitsa",
  "certificate_id": "unit-certificate",
  "issuer": "https://api.hyperone.com/v2/iam/project/unitproject/sa/unitsa",
  "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAKj34GkxFhD91assbzO39gyMDL7O+8/HG1V8b\n-----END RSA PRIVATE KEY-----",
  "public_key": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOB\n-----END PUBLIC KEY-----"
}`

// Review Focus: hyperone's NewDNSProviderConfig reads HYPERONE_PASSPORT_LOCATION
// eagerly via internal.LoadPassportFile, so construction from an inline
// passport must succeed with the temp file gone afterward.
func TestHyperoneBuildsFromInlinePassport(t *testing.T) {
	p, err := Build("hyperone", map[string]string{
		"HYPERONE_PASSPORT": hyperonePassportJSON,
	})
	if err != nil {
		t.Fatalf("want success building hyperone from an inline passport, got: %v", err)
	}
	if p == nil {
		t.Fatal("want a non-nil provider")
	}
}

// Review Focus: transip and hyperone must no longer be marked unsupported
// once their inline fields exist, but their server-path fields
// (TRANSIP_PRIVATE_KEY_PATH, HYPERONE_PASSPORT_LOCATION) must keep being
// rejected by SplitConfig — the API still never accepts a path on the
// server's own filesystem, only the new inline field.
func TestSchemasNoLongerUnsupported(t *testing.T) {
	for _, code := range []string{"transip", "hyperone"} {
		m, ok := Lookup(code)
		if !ok {
			t.Fatalf("%s: not registered", code)
		}
		if m.Unsupported {
			t.Fatalf("%s: still marked unsupported: %s", code, m.UnsupportedReason)
		}
	}

	if pub, sec, err := SplitConfig("transip", map[string]string{"TRANSIP_PRIVATE_KEY": "pem"}); err != nil {
		t.Fatalf("transip inline field rejected: %v", err)
	} else if sec["TRANSIP_PRIVATE_KEY"] != "pem" || len(pub) != 0 {
		t.Fatalf("transip inline field not stored as secret: pub=%v sec=%v", pub, sec)
	}
	if _, _, err := SplitConfig("transip", map[string]string{"TRANSIP_PRIVATE_KEY_PATH": "/etc/secrets/transip.key"}); err == nil {
		t.Fatal("transip TRANSIP_PRIVATE_KEY_PATH must still be rejected")
	}

	if pub, sec, err := SplitConfig("hyperone", map[string]string{"HYPERONE_PASSPORT": "{}"}); err != nil {
		t.Fatalf("hyperone inline field rejected: %v", err)
	} else if sec["HYPERONE_PASSPORT"] != "{}" || len(pub) != 0 {
		t.Fatalf("hyperone inline field not stored as secret: pub=%v sec=%v", pub, sec)
	}
	if _, _, err := SplitConfig("hyperone", map[string]string{"HYPERONE_PASSPORT_LOCATION": "/etc/secrets/passport.json"}); err == nil {
		t.Fatal("hyperone HYPERONE_PASSPORT_LOCATION must still be rejected")
	}
}
