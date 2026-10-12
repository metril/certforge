package api

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/notify/httpx"
)

// tlsPeekSlots bounds concurrent TLS peeks (each dials an arbitrary host and
// can hang for its timeout), as dnsTestSlots does.
var tlsPeekSlots = make(chan struct{}, 2)

var errTLSPeekBusy = &HTTPError{Status: http.StatusServiceUnavailable, Title: "Service busy",
	Detail: "Too many concurrent certificate lookups; retry shortly."}

// PeekTls returns the certificate chain a server presents. Connection
// failures are 200 with ok false.
func (s *Server) PeekTls(ctx context.Context, r gen.PeekTlsRequestObject) (gen.PeekTlsResponseObject, error) {
	if _, err := authorizeAny(ctx, &r.OrgId, authz.ActionDeliveryWrite, authz.ActionCAsWrite); err != nil {
		return nil, err
	}
	host, port, err := httpx.ParsePeekTarget(r.Body.Url)
	if err != nil {
		return nil, unprocessable("url", err.Error())
	}
	allow, err := s.monitorAllowLoopback(ctx)
	if err != nil {
		return nil, err
	}
	if err := challenge.CheckURLResolved(ctx, "https://"+hostPort(host, port), allow, s.d.HostResolver); err != nil {
		return nil, unprocessable("url", err.Error())
	}
	sni := ""
	if r.Body.Sni != nil {
		sni = strings.TrimSpace(*r.Body.Sni)
	}
	select {
	case tlsPeekSlots <- struct{}{}:
		defer func() { <-tlsPeekSlots }()
	default:
		writeRetryAfter(ctx, "5")
		return nil, errTLSPeekBusy
	}
	out := gen.TlsPeekResult{Chain: []gen.TlsPeekCertificate{}}
	chain, verified, perr := httpx.Peek(ctx, host, port, sni, allow)
	if perr != nil {
		out.Error = ptr(perr.Error())
	} else {
		out.Ok, out.Verified = true, verified
		for _, c := range chain {
			out.Chain = append(out.Chain, peekCert(c))
		}
	}
	s.audit(ctx, audit.Event{Action: "tls.peek", ResourceType: "org", OrgID: &r.OrgId,
		Details: map[string]any{"url": r.Body.Url}})
	return gen.PeekTls200JSONResponse(out), nil
}

func hostPort(host, port string) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port
	}
	return host + ":" + port
}

func peekCert(c *x509.Certificate) gen.TlsPeekCertificate {
	sum := sha256.Sum256(c.Raw)
	parts := make([]string, len(sum))
	for i, b := range sum {
		parts[i] = fmt.Sprintf("%02X", b)
	}
	return gen.TlsPeekCertificate{
		Subject: c.Subject.String(), Issuer: c.Issuer.String(), NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		Sha256: strings.Join(parts, ":"), IsCa: c.IsCA,
		SelfSigned: c.CheckSignatureFrom(c) == nil && c.Subject.String() == c.Issuer.String(),
		Pem:        string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})),
	}
}
