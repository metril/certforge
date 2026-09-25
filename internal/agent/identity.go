package agent

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
)

// Files in the data directory.
const (
	keyFile   = "agent.key"
	certFile  = "agent.crt"
	caFile    = "ca.pem"
	stateFile = "state.json"
)

// ErrNotEnrolled means the data directory has no agent certificate yet.
var ErrNotEnrolled = errors.New("agent: not enrolled")

// GrantState is what the agent installed for one grant, in write order.
type GrantState struct {
	VersionID       uuid.UUID             `json:"versionId"`
	CertificateName string                `json:"certificateName"`
	Files           []agentproto.FileSpec `json:"files"`
}

// State is state.json.
type State struct {
	AgentURL  string                   `json:"agentUrl"`
	ClientID  uuid.UUID                `json:"clientId"`
	TokenHash string                   `json:"tokenHash"` // hex sha256 of the token this identity came from
	Revision  int64                    `json:"revision"`
	Grants    map[uuid.UUID]GrantState `json:"grants"`
}

// Identity is the agent's key, certificate, trusted CAs and state.
type Identity struct {
	Dir   string
	Key   *ecdsa.PrivateKey
	Cert  *x509.Certificate
	CAs   *x509.CertPool
	State State
}

// TokenHashHex is how state.json records the enrolment token.
func TokenHashHex(token string) string { return hex.EncodeToString(agentproto.TokenHash(token)) }

// writeAtomic writes p through a temp file in the same directory: write,
// chmod, optional chown, fsync, rename, then fsync the directory.
func writeAtomic(p string, data []byte, mode fs.FileMode, chown func(*os.File) error) error {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+filepath.Base(p)+".tmp-*")
	if err != nil {
		return err
	}
	tmp, done := f.Name(), false
	defer func() {
		if !done {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if chown != nil {
		if err := chown(f); err != nil {
			return err
		}
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		return err
	}
	done = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}

func loadOrCreateKey(dir string) (*ecdsa.PrivateKey, error) {
	p := filepath.Join(dir, keyFile)
	if b, err := os.ReadFile(p); err == nil {
		return parseKey(b)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return key, writeAtomic(p, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600, nil)
}

func parseKey(b []byte) (*ecdsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("agent: agent.key is not PEM")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("agent: agent.key: %w", err)
	}
	key, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("agent: agent.key is %T, want ECDSA", k)
	}
	return key, nil
}

func csrPEM(key *ecdsa.PrivateKey) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "certforge-agent"}}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

func parseCert(certPEM []byte, key *ecdsa.PrivateKey) (*x509.Certificate, error) {
	blk, _ := pem.Decode(certPEM)
	if blk == nil {
		return nil, errors.New("agent: certificate is not PEM")
	}
	cert, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	if !key.PublicKey.Equal(cert.PublicKey) {
		return nil, errors.New("agent: certificate does not match agent.key")
	}
	return cert, nil
}

func parseBundle(b []byte) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(b) {
		return nil, errors.New("agent: trust bundle has no certificates")
	}
	return pool, nil
}

// LoadIdentity reads the data directory; ErrNotEnrolled when agent.crt is absent.
func LoadIdentity(dir string) (*Identity, error) {
	certPEM, err := os.ReadFile(filepath.Join(dir, certFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotEnrolled
	}
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, keyFile))
	if err != nil {
		return nil, err
	}
	key, err := parseKey(keyPEM)
	if err != nil {
		return nil, err
	}
	cert, err := parseCert(certPEM, key)
	if err != nil {
		return nil, err
	}
	caPEM, err := os.ReadFile(filepath.Join(dir, caFile))
	if err != nil {
		return nil, err
	}
	pool, err := parseBundle(caPEM)
	if err != nil {
		return nil, err
	}
	id := &Identity{Dir: dir, Key: key, Cert: cert, CAs: pool}
	b, err := os.ReadFile(filepath.Join(dir, stateFile))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, &id.State); err != nil {
		return nil, fmt.Errorf("agent: state.json: %w", err)
	}
	if id.State.Grants == nil {
		id.State.Grants = map[uuid.UUID]GrantState{}
	}
	return id, nil
}

// TLSCertificate is the client certificate presented to the server.
func (id *Identity) TLSCertificate() tls.Certificate {
	return tls.Certificate{Certificate: [][]byte{id.Cert.Raw}, PrivateKey: id.Key, Leaf: id.Cert}
}

// SaveState writes state.json (0600).
func (id *Identity) SaveState() error {
	b, err := json.MarshalIndent(id.State, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(id.Dir, stateFile), b, 0o600, nil)
}

// saveCert installs a new certificate and trust bundle.
func (id *Identity) saveCert(certPEM, bundle []byte) error {
	cert, err := parseCert(certPEM, id.Key)
	if err != nil {
		return err
	}
	pool, err := parseBundle(bundle)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(id.Dir, certFile), certPEM, 0o644, nil); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(id.Dir, caFile), bundle, 0o644, nil); err != nil {
		return err
	}
	id.Cert, id.CAs = cert, pool
	return nil
}

// SaveBundle replaces ca.pem after a trust_bundle_update.
func (id *Identity) SaveBundle(bundle []byte) error {
	pool, err := parseBundle(bundle)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(id.Dir, caFile), bundle, 0o644, nil); err != nil {
		return err
	}
	id.CAs = pool
	return nil
}
