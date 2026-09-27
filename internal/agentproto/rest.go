package agentproto

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// Facts describe the agent host.
type Facts struct {
	Hostname     string `json:"hostname"`
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	AgentVersion string `json:"agentVersion"`
}

// EnrollRequest is POST /agent/v1/enroll.
type EnrollRequest struct {
	Token string `json:"token"`
	CSR   string `json:"csr"` // PEM CERTIFICATE REQUEST
	Facts Facts  `json:"facts"`
}

// EnrollResponse carries the agent certificate and the trust bundle.
type EnrollResponse struct {
	Certificate string    `json:"certificate"` // PEM
	TrustBundle string    `json:"trustBundle"` // PEM, every trusted agent CA
	AgentURL    string    `json:"agentUrl"`
	ClientID    uuid.UUID `json:"clientId"`
}

// RenewRequest is POST /agent/v1/renew.
type RenewRequest struct {
	CSR string `json:"csr"`
}

// RenewResponse is a fresh agent certificate and the current trust bundle.
type RenewResponse struct {
	Certificate string `json:"certificate"`
	TrustBundle string `json:"trustBundle"`
}

// FileSpec is one file a grant installs, with the sha256 it must have.
type FileSpec struct {
	Path   string `json:"path"`
	Owner  string `json:"owner"`
	Group  string `json:"group"`
	Mode   string `json:"mode"`
	SHA256 string `json:"sha256"`
}

// FileDigest is a path and the sha256 of its content.
type FileDigest struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

// InstalledFile is one heartbeat entry; SHA256 is empty for a missing file.
type InstalledFile struct {
	GrantID uuid.UUID `json:"grantId"`
	Path    string    `json:"path"`
	SHA256  string    `json:"sha256"`
	MTime   time.Time `json:"mtime"`
}

// Target is an agent-side deploy target and its config.
type Target struct {
	Type   string          `json:"type"`
	Config json.RawMessage `json:"config"`
}

// HookSpec is one hook a grant runs.
type HookSpec struct {
	ID             uuid.UUID `json:"id"`
	Phase          string    `json:"phase"`
	Argv           []string  `json:"argv"`
	TimeoutSeconds int       `json:"timeoutSeconds"`
}

// Assignment is one live grant with an issued version.
type Assignment struct {
	ID              uuid.UUID `json:"id"`
	CertificateID   uuid.UUID `json:"certificateId"`
	CertificateName string    `json:"certificateName"`
	// VersionID is nil for a live grant whose certificate has no version
	// yet (C3): Files then holds only the target's material-independent
	// files (today, a Traefik ACME router file), and the agent must
	// install those straight from Target's config, never by fetching
	// Bundle (which 404s "no issued version yet" for such a grant).
	VersionID *uuid.UUID `json:"versionId"`
	// RedeploySeq is bumped by an explicit Redeploy and by server-side
	// auto-remediation. The agent is level-triggered on the assignment: a
	// grant needs redeploying when it has no saved state, or when
	// VersionID, RedeploySeq or Files differ from what it last wrote —
	// never when the on-disk bytes merely look wrong (that is reported,
	// and drift marked, only through the heartbeat's installed digests).
	RedeploySeq int64      `json:"redeploySeq"`
	Fingerprint string     `json:"fingerprint"`
	Delivery    string     `json:"delivery"`
	Files       []FileSpec `json:"files"`
	Target      *Target    `json:"target"`
	Hooks       []HookSpec `json:"hooks"`
}

// Removal is a deleted grant whose files the agent must remove.
type Removal struct {
	ID     uuid.UUID `json:"id"`
	Files  []string  `json:"files"`
	Target *Target   `json:"target"`
}

// Assignments is GET /agent/v1/assignments.
type Assignments struct {
	Revision int64        `json:"revision"`
	Grants   []Assignment `json:"grants"`
	Removed  []Removal    `json:"removed"`
}

// BundleFile is one rendered layout file.
type BundleFile struct {
	Path    string `json:"path"`
	Owner   string `json:"owner"`
	Group   string `json:"group"`
	Mode    string `json:"mode"`
	Content []byte `json:"contentBase64"`
}

// Material is PEM for an agent-side target to render its own files from.
type Material struct {
	Fullchain []byte `json:"fullchainPem"`
	Key       []byte `json:"keyPem"`
}

// Bundle is GET /agent/v1/grants/{id}/bundle.
type Bundle struct {
	VersionID uuid.UUID    `json:"versionId"`
	Files     []BundleFile `json:"files"`
	Material  *Material    `json:"material,omitempty"`
}

// HookRun is one hook execution.
type HookRun struct {
	HookID     uuid.UUID `json:"hookId"`
	Phase      string    `json:"phase"`
	Argv       []string  `json:"argv"`
	ExitCode   int       `json:"exitCode"`
	DurationMS int64     `json:"durationMs"`
	Stdout     string    `json:"stdout"`
	Stderr     string    `json:"stderr"`
}

// GrantResult is the outcome for one grant.
type GrantResult struct {
	GrantID   uuid.UUID    `json:"grantId"`
	VersionID uuid.UUID    `json:"versionId"`
	State     string       `json:"state"`
	Installed []FileDigest `json:"installed"`
	Error     string       `json:"error,omitempty"`
	HookRuns  []HookRun    `json:"hookRuns,omitempty"`
}

// Report is POST /agent/v1/report and the deploy_result message.
type Report struct {
	Revision int64         `json:"revision"`
	Results  []GrantResult `json:"results"`
}

// RenewDue reports whether two thirds of a certificate's lifetime have passed.
func RenewDue(notBefore, notAfter, now time.Time) bool {
	return !now.Before(notBefore.Add(notAfter.Sub(notBefore) * 2 / 3))
}

// CertFingerprint is the lowercase hex sha256 of a DER certificate.
func CertFingerprint(der []byte) string {
	s := sha256.Sum256(der)
	return hex.EncodeToString(s[:])
}
