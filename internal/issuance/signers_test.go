package issuance

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/crypto/cryptotest"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/signer"
	"github.com/metril/certforge/internal/signer/localca"
)

// TestCASecretFallsBackToTrustBundlePemWhenChainPemEmpty covers the
// batch-3 re-review fix: a localca CA row created before ChainPem existed
// (f5fccdc) has an empty config.chainPem. CASecret must still recover
// Material.Root/Chain from the CA's own trust_bundle_pem instead of
// leaving them empty, or such a CA would silently stop being able to
// issue/revoke/build a CRL after an upgrade.
func TestCASecretFallsBackToTrustBundlePemWhenChainPemEmpty(t *testing.T) {
	mat, _, err := localca.Generate(localca.Config{Subject: localca.Subject{CommonName: "Legacy"},
		KeyType: signer.EC256, RootValidityYears: 10, IssuingValidityYears: 3, MaxLeafDays: 397, CRL: true}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	issuingPKCS8, err := x509.MarshalPKCS8PrivateKey(mat.IssuingKey)
	if err != nil {
		t.Fatal(err)
	}

	// ChainPem deliberately left empty: simulates a row written before the
	// batch-3 review fix added the field.
	cfg := localCAConfig{Subject: localCASubject{CommonName: "Legacy"}, KeyType: string(signer.EC256),
		RootValidityYears: 10, IssuingValidityYears: 3, MaxLeafDays: 397, CRL: true, IssuingPem: pemEncodeCert(mat.Issuing)}
	cfgRaw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}

	box := cryptotest.PrefixBox{}
	secRaw, err := json.Marshal(localCASecretCfg{IssuingKey: issuingPKCS8})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := box.Seal(context.Background(), secRaw)
	if err != nil {
		t.Fatal(err)
	}

	row := sqlcgen.Ca{ID: uuid.New(), OrgID: uuid.New(), Type: CATypeLocalCA, Config: cfgRaw, SecretCfg: sealed,
		TrustBundlePem: pemEncodeCert(mat.Root)}

	s := NewStore(nil, box, nil)
	got, _, err := s.CASecret(context.Background(), row, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Root == nil {
		t.Fatal("Root is nil: fallback to trust_bundle_pem did not run")
	}
	if got.Root.SerialNumber.Cmp(mat.Root.SerialNumber) != 0 {
		t.Fatalf("Root serial = %v, want %v", got.Root.SerialNumber, mat.Root.SerialNumber)
	}
	if len(got.Chain) != 1 {
		t.Fatalf("Chain = %d entries, want 1 (the root, recovered from trust_bundle_pem)", len(got.Chain))
	}
}
