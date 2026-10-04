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
	"strings"
	"sync"
	"time"

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
	VersionID uuid.UUID `json:"versionId"`
	// RedeploySeq is the assignment's RedeploySeq as of the last successful
	// deploy; see needsDeploy.
	RedeploySeq     int64                 `json:"redeploySeq"`
	CertificateName string                `json:"certificateName"`
	Files           []agentproto.FileSpec `json:"files"`
	// CertsDir is the certs/<name> directory Deploy's Traefik target created
	// for this grant (see Deployer.Deploy), or "" when the grant has no
	// target. Reconcile stores it exactly as Deploy returned it, rather than
	// guessing it back from file names, so a removal prunes only a directory
	// this grant's own target actually created.
	CertsDir string `json:"certsDir,omitempty"`
	// Pending marks that the last deploy attempt for this grant did not
	// reach agentproto.StateOK. The rest of the struct is left exactly as
	// it was after this grant's last successful deploy (not overwritten
	// with whatever the failed attempt wrote), so stale/orphan cleanup can
	// still find and remove those old files once the assignment moves on
	// to something else, even though this deploy never confirmed writing
	// its replacement. needsDeploy always retries while this is set,
	// regardless of whether the assignment's version, redeploySeq and
	// files still match this (stale) state.
	Pending bool `json:"pending,omitempty"`
}

// State is state.json.
type State struct {
	AgentURL  string                   `json:"agentUrl"`
	ClientID  uuid.UUID                `json:"clientId"`
	TokenHash string                   `json:"tokenHash"` // hex sha256 of the token this identity came from
	Revision  int64                    `json:"revision"`
	Grants    map[uuid.UUID]GrantState `json:"grants"`
}

// Identity is the agent's key, certificate, trusted CAs and state. Cert and
// CAs (and the derived State.ClientID) can change under a concurrent renewal
// or trust-bundle update while a TLS handshake reads them, so every access
// to those fields outside of construction goes through mu.
type Identity struct {
	Dir   string
	Key   *ecdsa.PrivateKey
	Cert  *x509.Certificate
	CAs   *x509.CertPool
	State State

	mu sync.Mutex
}

// clientURIPrefix matches agentca.ClientURI's scheme. The client id is
// derived from the certificate's own URI SAN, never trusted from state.json,
// so a stale or hand-edited state file can never claim to be a different
// client than the certificate actually proves.
const clientURIPrefix = "urn:certforge:client:"

func clientIDFromCert(c *x509.Certificate) (uuid.UUID, error) {
	if len(c.URIs) != 1 || !strings.HasPrefix(c.URIs[0].String(), clientURIPrefix) {
		return uuid.Nil, errors.New("agent: certificate has no client id URI SAN")
	}
	id, err := uuid.Parse(strings.TrimPrefix(c.URIs[0].String(), clientURIPrefix))
	if err != nil {
		return uuid.Nil, fmt.Errorf("agent: certificate client id: %w", err)
	}
	return id, nil
}

// TokenHashHex is how state.json records the enrolment token.
func TokenHashHex(token string) string { return hex.EncodeToString(agentproto.TokenHash(token)) }

// writeAtomic writes p through a temp file in the same directory: write,
// chmod, optional chown, fsync, rename, then fsync the directory.
func writeAtomic(p string, data []byte, mode fs.FileMode, chown func(*os.File) error) error {
	tmp, err := stageAtomic(p, data, mode, chown)
	if err != nil {
		return err
	}
	return commitStaged(tmp, p)
}

// stageAtomic writes data to a temp sibling of p (fsynced, chmod, chown) and
// returns its path, leaving p itself untouched; commitStaged or os.Remove
// finishes it. The temp is removed on error.
func stageAtomic(p string, data []byte, mode fs.FileMode, chown func(*os.File) error) (string, error) {
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, parentDirMode(mode)); err != nil {
		return "", err
	}
	sweepStale(dir, "."+filepath.Base(p)+".tmp-")
	f, err := os.CreateTemp(dir, "."+filepath.Base(p)+".tmp-*")
	if err != nil {
		return "", err
	}
	tmp, done := f.Name(), false
	defer func() {
		if !done {
			_ = f.Close()
			_ = os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		return "", err
	}
	if err := f.Chmod(mode); err != nil {
		return "", err
	}
	if chown != nil {
		if err := chown(f); err != nil {
			return "", err
		}
	}
	if err := f.Sync(); err != nil {
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	done = true
	return tmp, nil
}

// parentDirMode is the mode for parent directories created for a file of the
// given mode: the file's read bits become traverse bits and the owner always
// gets full access, so a 0600 secret gets 0700 dirs and 0640 gets 0750.
// Directories that already exist are never touched.
func parentDirMode(mode fs.FileMode) fs.FileMode {
	m := mode.Perm()
	return m | (m&0o444)>>2 | 0o700
}

// staleTempAge is how old a leftover temp must be before sweepStale removes
// it, so a concurrent writer's live temp is never taken.
const staleTempAge = time.Minute

// sweepStale removes crash leftovers (prefix+random temp siblings) in dir.
func sweepStale(dir, prefix string) {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range ents {
		if !strings.HasPrefix(e.Name(), prefix) || e.IsDir() {
			continue
		}
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > staleTempAge {
			_ = os.Remove(filepath.Join(dir, e.Name()))
		}
	}
}

// commitStaged renames tmp over p and syncs the directory; tmp is removed
// when the rename fails.
func commitStaged(tmp, p string) error {
	if err := os.Rename(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	d, err := os.Open(filepath.Dir(p))
	if err != nil {
		return err
	}
	if err := d.Sync(); err != nil {
		_ = d.Close()
		return err
	}
	return d.Close()
}

// requireHTTPS rejects a non-empty agent URL that is not https, so a server
// response or an edited state.json cannot steer the agent to a cleartext
// endpoint (Dial and ParseToken apply the same rule).
func requireHTTPS(u string) error {
	if u != "" && !strings.HasPrefix(u, "https://") {
		return fmt.Errorf("agent: agent URL %q is not https", u)
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
	clientID, err := clientIDFromCert(cert)
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
	if err := requireHTTPS(id.State.AgentURL); err != nil {
		return nil, err
	}
	id.State.ClientID = clientID // the certificate's URI SAN is authoritative, not the stored value
	if id.State.Grants == nil {
		id.State.Grants = map[uuid.UUID]GrantState{}
	}
	return id, nil
}

// current returns the live certificate and CA pool under the identity's
// lock, safe to call concurrently with a renewal or bundle update running
// in another goroutine.
func (id *Identity) current() (*x509.Certificate, *x509.CertPool) {
	id.mu.Lock()
	defer id.mu.Unlock()
	return id.Cert, id.CAs
}

// TLSCertificate is the client certificate presented to the server.
func (id *Identity) TLSCertificate() tls.Certificate {
	cert, _ := id.current()
	return tls.Certificate{Certificate: [][]byte{cert.Raw}, PrivateKey: id.Key, Leaf: cert}
}

// SaveState writes state.json (0600).
func (id *Identity) SaveState() error {
	id.mu.Lock()
	b, err := json.MarshalIndent(id.State, "", "  ")
	id.mu.Unlock()
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(id.Dir, stateFile), b, 0o600, nil)
}

// commitBundle validates and writes ca.pem, then swaps in the new pool
// under the identity's lock so a handshake in another goroutine never sees
// a half-updated pool.
func (id *Identity) commitBundle(bundle []byte) error {
	pool, err := parseBundle(bundle)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(id.Dir, caFile), bundle, 0o644, nil); err != nil {
		return err
	}
	id.mu.Lock()
	id.CAs = pool
	id.mu.Unlock()
	return nil
}

// commitCert validates certPEM against id.Key, writes agent.crt (the
// identity's "enrolled" marker: LoadIdentity treats its absence as
// ErrNotEnrolled whatever else is present) and swaps in the new certificate
// and its derived client id under the identity's lock.
func (id *Identity) commitCert(certPEM []byte) error {
	cert, err := parseCert(certPEM, id.Key)
	if err != nil {
		return err
	}
	clientID, err := clientIDFromCert(cert)
	if err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(id.Dir, certFile), certPEM, 0o644, nil); err != nil {
		return err
	}
	id.mu.Lock()
	id.Cert, id.State.ClientID = cert, clientID
	id.mu.Unlock()
	return nil
}

// saveCert installs a new certificate and trust bundle. Both are validated
// before anything is written, and the write order after that is bundle then
// cert, so a crash mid-renewal never leaves a certificate on disk that the
// current trust bundle can't vouch for, and never swaps the two the other
// way round.
func (id *Identity) saveCert(certPEM, bundle []byte) error {
	if _, err := parseCert(certPEM, id.Key); err != nil {
		return err
	}
	if _, err := parseBundle(bundle); err != nil {
		return err
	}
	if err := id.commitBundle(bundle); err != nil {
		return err
	}
	return id.commitCert(certPEM)
}

// SaveBundle replaces ca.pem after a trust_bundle_update.
func (id *Identity) SaveBundle(bundle []byte) error {
	return id.commitBundle(bundle)
}
