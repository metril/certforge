package api

import (
	"context"
	"net/http"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agents"
	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
)

func enrollmentRequestsOut(items []agents.PendingEnrollment) gen.EnrollmentRequestList {
	out := make([]gen.EnrollmentRequest, 0, len(items))
	for _, p := range items {
		out = append(out, gen.EnrollmentRequest{Id: p.ID, OrgId: p.OrgID, ClientId: p.ClientID, ClientName: p.ClientName, SiteId: p.SiteID,
			VerifyCode: p.VerifyCode, KeyFingerprint: p.PubkeyFingerprint, Hostname: p.Facts.Hostname, Os: p.Facts.OS, Arch: p.Facts.Arch,
			AgentVersion: p.Facts.AgentVersion, SourceIp: p.SourceIP, CreatedAt: p.CreatedAt, ExpiresAt: p.ExpiresAt})
	}
	return gen.EnrollmentRequestList{Items: out}
}

// ListEnrollmentRequests lists an org's enrolment requests waiting for approval.
func (s *Server) ListEnrollmentRequests(ctx context.Context, r gen.ListEnrollmentRequestsRequestObject) (gen.ListEnrollmentRequestsResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsRead, &r.OrgId); err != nil {
		return nil, err
	}
	items, err := s.d.Agents.ListPendingEnrollments(ctx, []uuid.UUID{r.OrgId})
	if err != nil {
		return nil, mapAgentErr(err)
	}
	return gen.ListEnrollmentRequests200JSONResponse(enrollmentRequestsOut(items)), nil
}

// ListAllEnrollmentRequests lists waiting requests across every org the caller can read.
func (s *Server) ListAllEnrollmentRequests(ctx context.Context, _ gen.ListAllEnrollmentRequestsRequestObject) (gen.ListAllEnrollmentRequestsResponseObject, error) {
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	orgs := authz.OrgsWith(p, authz.ActionClientsRead)
	if len(orgs) == 0 {
		return nil, &HTTPError{Status: http.StatusForbidden, Title: "Forbidden", Detail: "missing permission clients:read"}
	}
	items, err := s.d.Agents.ListPendingEnrollments(ctx, orgs)
	if err != nil {
		return nil, mapAgentErr(err)
	}
	return gen.ListAllEnrollmentRequests200JSONResponse(enrollmentRequestsOut(items)), nil
}

// ApproveEnrollmentRequest lets the waiting agent collect its certificate.
func (s *Server) ApproveEnrollmentRequest(ctx context.Context, r gen.ApproveEnrollmentRequestRequestObject) (gen.ApproveEnrollmentRequestResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if err := s.d.Agents.ApproveEnrollment(ctx, r.OrgId, r.Id); err != nil {
		return nil, mapAgentErr(err)
	}
	return gen.ApproveEnrollmentRequest204Response{}, nil
}

// RejectEnrollmentRequest refuses a waiting request.
func (s *Server) RejectEnrollmentRequest(ctx context.Context, r gen.RejectEnrollmentRequestRequestObject) (gen.RejectEnrollmentRequestResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionClientsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	if err := s.d.Agents.RejectEnrollment(ctx, r.OrgId, r.Id); err != nil {
		return nil, mapAgentErr(err)
	}
	return gen.RejectEnrollmentRequest204Response{}, nil
}
