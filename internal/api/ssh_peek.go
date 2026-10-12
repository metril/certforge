package api

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/targets/sshx"
)

// sshPeekSlots bounds concurrent SSH host key peeks, as tlsPeekSlots does.
var sshPeekSlots = make(chan struct{}, 2)

var errSSHPeekBusy = &HTTPError{Status: http.StatusServiceUnavailable, Title: "Service busy",
	Detail: "Too many concurrent host key lookups; retry shortly."}

// PeekSSHHostKey returns the host keys an SSH server offers. Connection
// failures are 200 with ok false.
func (s *Server) PeekSSHHostKey(ctx context.Context, r gen.PeekSSHHostKeyRequestObject) (gen.PeekSSHHostKeyResponseObject, error) {
	if _, err := authorizeAny(ctx, &r.OrgId, authz.ActionDeliveryWrite); err != nil {
		return nil, err
	}
	host := strings.TrimSpace(r.Body.Host)
	if host == "" {
		return nil, unprocessable("host", "required")
	}
	port := 22
	if r.Body.Port != nil {
		port = *r.Body.Port
	}
	if port < 1 || port > 65535 {
		return nil, unprocessable("port", "must be 1-65535")
	}
	allow, err := s.monitorAllowLoopback(ctx)
	if err != nil {
		return nil, err
	}
	if err := challenge.CheckURLResolved(ctx, "https://"+hostPort(host, strconv.Itoa(port)), allow, s.d.HostResolver); err != nil {
		return nil, unprocessable("host", err.Error())
	}
	select {
	case sshPeekSlots <- struct{}{}:
		defer func() { <-sshPeekSlots }()
	default:
		writeRetryAfter(ctx, "5")
		return nil, errSSHPeekBusy
	}
	out := gen.SshPeekResult{Keys: []gen.SshPeekHostKey{}}
	keys, perr := sshx.ScanHostKeys(ctx, host, port, allow)
	if perr != nil {
		out.Error = ptr(perr.Error())
	} else {
		out.Ok = true
		for _, k := range keys {
			out.Keys = append(out.Keys, gen.SshPeekHostKey{Type: k.Type, Key: k.Line, Sha256: k.Sha256})
		}
	}
	s.audit(ctx, audit.Event{Action: "ssh.peek", ResourceType: "org", OrgID: &r.OrgId,
		Details: map[string]any{"host": host, "port": port}})
	return gen.PeekSSHHostKey200JSONResponse(out), nil
}
