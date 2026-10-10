package agent

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
)

type tlsFixture struct {
	agentLeaf, sysLeaf *x509.Certificate // server certificates for 127.0.0.1
	agentPool, sysPool *x509.CertPool
}

func newTLSFixture(t *testing.T) tlsFixture {
	t.Helper()
	now := time.Now()
	aCert, aKey, err := agentca.NewCA(now)
	if err != nil {
		t.Fatal(err)
	}
	aLeaf, err := agentca.SignServer(&agentca.CA{Cert: aCert, Key: aKey}, &mustKey(t).PublicKey, []string{"127.0.0.1"}, now)
	if err != nil {
		t.Fatal(err)
	}
	sCert, sKey := testRoot(t, "public root")
	sLeaf := testLeaf(t, sCert, sKey, "127.0.0.1")
	f := tlsFixture{agentLeaf: aLeaf, sysLeaf: sLeaf, agentPool: x509.NewCertPool(), sysPool: x509.NewCertPool()}
	f.agentPool.AddCert(aCert)
	f.sysPool.AddCert(sCert)
	return f
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func testRoot(t *testing.T, cn string) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	k := mustKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

func testLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, ip string) *x509.Certificate {
	t.Helper()
	k := mustKey(t)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: ip},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames: []string{"proxy.example"}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &k.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c
}

// The TLS roots follow the transport mode; the application layer's security
// does not depend on them.
func TestVerifyServerTLSModes(t *testing.T) {
	f := newTLSFixture(t)
	state := func(c *x509.Certificate, name string) tls.ConnectionState {
		return tls.ConnectionState{PeerCertificates: []*x509.Certificate{c}, ServerName: name}
	}
	for _, tc := range []struct {
		mode      string
		cert      *x509.Certificate
		name      string
		wantAllow bool
	}{
		{TransportAuto, f.agentLeaf, "127.0.0.1", true},   // agent-CA chain: the pin
		{TransportAuto, f.sysLeaf, "proxy.example", true}, // a public chain: system roots
		{TransportAuto, f.agentLeaf, "other.example", false},
		{TransportAuto, f.sysLeaf, "other.example", false},
		{TransportMTLS, f.agentLeaf, "127.0.0.1", true},
		{TransportMTLS, f.sysLeaf, "proxy.example", false},
		{TransportProxy, f.sysLeaf, "proxy.example", true},
		{TransportProxy, f.agentLeaf, "127.0.0.1", false},
		{"", f.sysLeaf, "proxy.example", true}, // empty is auto
	} {
		err := verifyServerTLS(tc.mode, state(tc.cert, tc.name), f.agentPool, f.sysPool)
		if (err == nil) != tc.wantAllow {
			t.Errorf("mode %q cert %s name %s: err = %v, allow = %v", tc.mode, tc.cert.Subject.CommonName, tc.name, err, tc.wantAllow)
		}
	}
	if err := verifyServerTLS(TransportAuto, tls.ConnectionState{}, f.agentPool, f.sysPool); err == nil {
		t.Error("a server with no certificate accepted")
	}
}

func TestParseTransport(t *testing.T) {
	for in, want := range map[string]string{"": TransportAuto, "AUTO": TransportAuto, " mtls ": TransportMTLS, "proxy": TransportProxy} {
		if got, err := ParseTransport(in); err != nil || got != want {
			t.Errorf("%q -> %q, %v", in, got, err)
		}
	}
	if _, err := ParseTransport("tls"); err == nil {
		t.Error("unknown transport accepted")
	}
	if _, err := LoadConfig(func(k string) string {
		if k == "CF_AGENT_TRANSPORT" {
			return "nope"
		}
		return ""
	}, "t"); err == nil {
		t.Error("LoadConfig accepted an unknown transport")
	}
	cfg, err := LoadConfig(func(string) string { return "" }, "t")
	if err != nil || cfg.Transport != TransportAuto {
		t.Errorf("default transport %q, %v", cfg.Transport, err)
	}
}

func certPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

// A trust_bundle_update may drop CAs and add only ones that chain to the
// current bundle; an independent new root is never taken from the message.
func TestApplyTrustUpdate(t *testing.T) {
	root, rootKey := testRoot(t, "root")
	other, _ := testRoot(t, "other root")
	rogue, _ := testRoot(t, "rogue")
	// An intermediate issued by the current root chains to it.
	ik := mustKey(t)
	itmpl := &x509.Certificate{SerialNumber: big.NewInt(77), Subject: pkix.Name{CommonName: "intermediate"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	ider, err := x509.CreateCertificate(rand.Reader, itmpl, root, &ik.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(ider)

	setup := func(initial ...*x509.Certificate) (*Agent, string) {
		dir := t.TempDir()
		pool := x509.NewCertPool()
		var b []byte
		for _, c := range initial {
			pool.AddCert(c)
			b = append(b, certPEM(c)...)
		}
		if err := os.WriteFile(filepath.Join(dir, caFile), b, 0o644); err != nil {
			t.Fatal(err)
		}
		return &Agent{Log: discard, Now: time.Now, ID: &Identity{Dir: dir, CAs: pool}}, filepath.Join(dir, caFile)
	}
	read := func(p string) string { b, _ := os.ReadFile(p); return string(b) }

	a, p := setup(root, other)
	a.applyTrustUpdate(string(certPEM(other))) // a retired CA is dropped
	if got := read(p); got != string(certPEM(other)) {
		t.Fatalf("subset not applied: %q", got)
	}
	a, p = setup(root)
	before := read(p)
	a.applyTrustUpdate(string(certPEM(root)) + string(certPEM(rogue)))
	if read(p) != before {
		t.Fatal("a bundle naming a CA that does not chain was applied")
	}
	a.applyTrustUpdate(string(certPEM(rogue)))
	if read(p) != before {
		t.Fatal("a bundle of only an unchained CA was applied")
	}
	a.applyTrustUpdate("not pem")
	if read(p) != before {
		t.Fatal("garbage replaced the bundle")
	}
	a.applyTrustUpdate(string(certPEM(root)) + string(certPEM(inter)))
	if got := read(p); got != string(certPEM(root))+string(certPEM(inter)) {
		t.Fatalf("a chained CA was not accepted: %q", got)
	}
}

// Only a signed refusal of the upgrade means revoked; a proxy's own 401 does not.
func TestDialUnsignedRefusalIsNotRevocation(t *testing.T) {
	f := newFakeServer(t)
	a := testAgent(t, f)
	f.with(func() { f.wsStatus = http.StatusForbidden })
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.session(ctx, nil); err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("session = %v", err)
	}
	f.with(func() { f.wsStatus = http.StatusUnauthorized; f.wsUnsigned = true })
	if err := a.session(ctx, nil); err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("an unsigned 401 on the upgrade = %v, want a transport error", err)
	}
}

// A close code is not authenticated, so 4001 alone does not stop the agent.
func TestCloseRevokedWithoutMessageIsNotRevocation(t *testing.T) {
	f := newFakeServer(t)
	a := testAgent(t, f)
	f.with(func() {
		f.onWS = func(ctx context.Context, c *fakeWS) { _ = c.Close(4001, "revoked") }
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.session(ctx, nil); err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("session = %v", err)
	}
}

// The agent refuses a responder certificate past its 24 h lifetime.
func TestExpiredResponderIsRefused(t *testing.T) {
	_, cl := enrolledClient(t)
	if _, err := cl.Assignments(context.Background()); err != nil {
		t.Fatal(err)
	}
	cl.st.now = func() time.Time { return time.Now().Add(48 * time.Hour) }
	cl.st.reset()
	if _, err := cl.Assignments(context.Background()); !errors.Is(err, ErrUnsigned) {
		t.Fatalf("expired responder: %v", err)
	}
}

// A revoked message that is not sealed (a proxy's forgery) ends the connection,
// not the agent.
func TestForgedRevokedIsIgnored(t *testing.T) {
	f := newFakeServer(t)
	a := testAgent(t, f)
	f.with(func() {
		f.onWS = func(ctx context.Context, c *fakeWS) {
			b, _ := agentproto.Marshal(agentproto.Revoked{})
			_ = c.Raw.Write(ctx, websocket.MessageText, b)
			_ = c.Raw.Write(ctx, websocket.MessageBinary, b)
			<-ctx.Done()
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.session(ctx, nil); err == nil || errors.Is(err, ErrRevoked) {
		t.Fatalf("session = %v", err)
	}
}

// A sealed trust_bundle_update naming a CA that does not chain to the bundle
// is not trusted; the agent takes the real bundle from the signed renewal.
func TestTrustUpdateWithRogueCAIsNotTrusted(t *testing.T) {
	f := newFakeServer(t)
	a := testAgent(t, f)
	rogue, _, err := agentca.NewCA(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	genuine := string(agentca.CertPEM(f.ca.Cert.Raw))
	f.with(func() {
		f.bundle = genuine
		f.onWS = sendAndWait(agentproto.TrustBundleUpdate{Bundle: genuine + string(agentca.CertPEM(rogue.Raw))})
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := a.session(ctx, nil); !errors.Is(err, errReconnect) {
		t.Fatalf("session = %v", err)
	}
	saved, _ := os.ReadFile(filepath.Join(a.ID.Dir, caFile))
	var renewals int
	f.with(func() { renewals = f.renewals })
	if string(saved) != genuine || renewals != 1 {
		t.Fatalf("bundle %q, renewals %d", saved, renewals)
	}
}
