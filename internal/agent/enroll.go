package agent

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentproto"
)

// verifyPinned accepts the server only if its chain contains the CA the
// token pins and the leaf verifies under it as a server certificate. The
// host name is not checked here: the pin is stronger than a name.
func verifyPinned(raw [][]byte, fp string) error {
	if len(raw) == 0 {
		return errors.New("agent: server sent no certificate")
	}
	certs := make([]*x509.Certificate, 0, len(raw))
	var anchor *x509.Certificate
	for _, r := range raw {
		c, err := x509.ParseCertificate(r)
		if err != nil {
			return err
		}
		certs = append(certs, c)
		if agentproto.CertFingerprint(c.Raw) == fp {
			anchor = c
		}
	}
	if anchor == nil {
		return errors.New("agent: the server's certificate chain does not contain the CA pinned by the token")
	}
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	_, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}})
	return err
}

func pinnedClient(fp string) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{
		MinVersion: tls.VersionTLS12,
		// Standard verification is replaced, not skipped: VerifyPeerCertificate
		// below requires the pinned CA and a valid chain to it.
		InsecureSkipVerify:    true, //nolint:gosec // pinned by VerifyPeerCertificate
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error { return verifyPinned(raw, fp) },
	}}
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// Enroll exchanges a one-time token for this agent's certificate. The key is
// created once (agent.key, 0600) and reused by later enrolments; grants
// already recorded in state.json are kept so a re-enrolled agent still
// knows which files it wrote.
func Enroll(ctx context.Context, dir, token string, facts agentproto.Facts) (*Identity, error) {
	tok, err := agentproto.ParseToken(token)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := loadOrCreateKey(dir)
	if err != nil {
		return nil, err
	}
	csr, err := csrPEM(key)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(agentproto.EnrollRequest{Token: strings.TrimSpace(token), CSR: string(csr), Facts: facts})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tok.AgentURL+"/agent/v1/enroll", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := pinnedClient(tok.CAFingerprint).Do(req)
	if err != nil {
		return nil, fmt.Errorf("enrol: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("enrol: %w", problemError(resp))
	}
	var er agentproto.EnrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return nil, fmt.Errorf("enrol: %w", err)
	}
	id := &Identity{Dir: dir, Key: key, State: State{Grants: map[uuid.UUID]GrantState{}}}
	if prev, err := os.ReadFile(filepath.Join(dir, stateFile)); err == nil {
		_ = json.Unmarshal(prev, &id.State)
		if id.State.Grants == nil {
			id.State.Grants = map[uuid.UUID]GrantState{}
		}
	}
	if err := id.saveCert([]byte(er.Certificate), []byte(er.TrustBundle)); err != nil {
		return nil, err
	}
	id.State.AgentURL = strings.TrimRight(er.AgentURL, "/")
	if id.State.AgentURL == "" {
		id.State.AgentURL = tok.AgentURL
	}
	id.State.ClientID, id.State.TokenHash, id.State.Revision = er.ClientID, TokenHashHex(token), 0
	if err := id.SaveState(); err != nil {
		return nil, err
	}
	return id, nil
}
