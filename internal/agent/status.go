package agent

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/metril/certforge/internal/agentproto"
)

// Status prints the agent's identity, certificate expiry and last revision.
func Status(w io.Writer, dir string, now time.Time) error {
	id, err := LoadIdentity(dir)
	if errors.Is(err, ErrNotEnrolled) {
		_, err := fmt.Fprintln(w, "Not enrolled. Set CF_AGENT_TOKEN or CF_AGENT_TOKEN_FILE, or run: certforge-agent enroll --token <token>")
		return err
	}
	if err != nil {
		return err
	}
	renew := "at two thirds of its lifetime"
	if agentproto.RenewDue(id.Cert.NotBefore, id.Cert.NotAfter, now) {
		renew = "due now"
	}
	_, err = fmt.Fprintf(w, "Client:        %s\nAgent URL:     %s\nCertificate:   serial %s, expires %s (renewal %s)\nRevision:      %d\nGrants:        %d\n",
		id.State.ClientID, id.State.AgentURL, id.Cert.SerialNumber.Text(16), id.Cert.NotAfter.UTC().Format(time.RFC3339),
		renew, id.State.Revision, len(id.State.Grants))
	return err
}
