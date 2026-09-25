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
	cert, _ := id.current()
	renew := "at two thirds of its lifetime"
	if agentproto.RenewDue(cert.NotBefore, cert.NotAfter, now) {
		renew = "due now"
	}
	_, err = fmt.Fprintf(w, "Client:        %s\nAgent URL:     %s\nCertificate:   serial %s, expires %s (renewal %s)\nRevision:      %d\nGrants:        %d\n",
		id.State.ClientID, id.State.AgentURL, cert.SerialNumber.Text(16), cert.NotAfter.UTC().Format(time.RFC3339),
		renew, id.State.Revision, len(id.State.Grants))
	return err
}
