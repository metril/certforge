package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/issuance"
)

// overviewCap bounds the briefs one summary returns; truncated says it bit.
const overviewCap = 2000

// GetCertificateOverview is the Overview's summary for one org.
func (s *Server) GetCertificateOverview(ctx context.Context, r gen.GetCertificateOverviewRequestObject) (gen.GetCertificateOverviewResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsRead, &r.OrgId); err != nil {
		return nil, err
	}
	out, err := s.certOverview(ctx, []uuid.UUID{r.OrgId})
	if err != nil {
		return nil, err
	}
	return gen.GetCertificateOverview200JSONResponse(out), nil
}

// GetAllCertificateOverview is GetCertificateOverview over every org the
// caller can read, authorised like ListAllCertificates.
func (s *Server) GetAllCertificateOverview(ctx context.Context, _ gen.GetAllCertificateOverviewRequestObject) (gen.GetAllCertificateOverviewResponseObject, error) {
	p, ok := authn.PrincipalFrom(ctx)
	if !ok {
		return nil, errUnauthenticated
	}
	orgs := authz.OrgsWith(p, authz.ActionCertsRead)
	if len(orgs) == 0 {
		return nil, &HTTPError{Status: http.StatusForbidden, Title: "Forbidden", Detail: "missing permission certs:read"}
	}
	out, err := s.certOverview(ctx, orgs)
	if err != nil {
		return nil, err
	}
	return gen.GetAllCertificateOverview200JSONResponse(out), nil
}

func hasManualDNS(rules []challenge.RuleSpec) bool {
	for _, r := range rules {
		if r.Method == challenge.MethodManualDNS {
			return true
		}
	}
	return false
}

// firstErrorLine is the first line of a certificate's last error, cut to 140
// characters (what the Overview shows as the cause).
func firstErrorLine(s string) *string {
	if s == "" {
		return nil
	}
	line, _, _ := strings.Cut(s, "\n")
	if r := []rune(line); len(r) > 140 {
		line = string(r[:140])
	}
	return &line
}

// certOverview computes the counts and the briefs. A certificate is waiting
// on manual DNS when its own rules (or, with none of its own, the rules it
// inherits) use manual-dns, resolved through the org defaults exactly as the
// certificate list does.
func (s *Server) certOverview(ctx context.Context, orgIDs []uuid.UUID) (gen.CertificateOverview, error) {
	st := s.d.Issuance.Store
	global, err := st.GlobalDefaults(ctx)
	if err != nil {
		return gen.CertificateOverview{}, err
	}
	orgDefaults := make(map[uuid.UUID]issuance.Defaults, len(orgIDs))
	var inherit []uuid.UUID
	for _, id := range orgIDs {
		d, err := st.OrgDefaults(ctx, id)
		if err != nil {
			return gen.CertificateOverview{}, err
		}
		orgDefaults[id] = d
		if hasManualDNS(issuance.Resolve(global, d, issuance.Defaults{}).VerificationRules.Value) {
			inherit = append(inherit, id)
		}
	}
	q := s.queries()
	cnt, err := q.CertificateOverviewCounts(ctx, orgIDs)
	if err != nil {
		return gen.CertificateOverview{}, err
	}
	var out gen.CertificateOverview
	for _, c := range cnt {
		n := int(c.N)
		out.Counts.Total += n
		switch c.Status {
		case issuance.StatusActive:
			out.Counts.Active += n
		case issuance.StatusPending:
			out.Counts.Pending += n
		case issuance.StatusFailed:
			out.Counts.Failed += n
		case issuance.StatusExpired:
			out.Counts.Expired += n
		case issuance.StatusRevoked:
			out.Counts.Revoked += n
			continue
		}
		out.Beyond += int(c.Beyond)
	}
	rows, err := q.CertificateOverviewBriefs(ctx, sqlcgen.CertificateOverviewBriefsParams{OrgIds: orgIDs, InheritOrgs: inherit, RowLimit: overviewCap + 1})
	if err != nil {
		return gen.CertificateOverview{}, err
	}
	if len(rows) > overviewCap {
		rows = rows[:overviewCap]
		out.Truncated = true
	}
	out.Items = make([]gen.CertificateBrief, 0, len(rows))
	for _, r := range rows {
		var own []challenge.RuleSpec
		if err := json.Unmarshal(r.VerificationRules, &own); err != nil {
			return gen.CertificateOverview{}, err
		}
		rules := own
		if len(own) == 0 {
			var ov issuance.Defaults
			if err := json.Unmarshal(r.Overrides, &ov); err != nil {
				return gen.CertificateOverview{}, err
			}
			rules = issuance.Resolve(global, orgDefaults[r.OrgID], ov).VerificationRules.Value
		}
		manual := hasManualDNS(rules)
		if !r.NeedsLook && !manual {
			continue
		}
		b := gen.CertificateBrief{Id: r.ID, OrgId: r.OrgID, Name: r.Name, Status: gen.CertificateBriefStatus(r.Status),
			NotBefore: r.NotBefore, NotAfter: r.NotAfter, NextRenewAt: r.NextRenewAt, FailureCount: int(r.FailureCount),
			LastErrorLine: firstErrorLine(r.LastError), ManualDns: manual}
		if r.AriWindowStart != nil && r.AriWindowEnd != nil && r.AriCheckedAt != nil {
			b.AriWindow = &gen.AriWindow{Start: *r.AriWindowStart, End: *r.AriWindowEnd, CheckedAt: *r.AriCheckedAt}
		}
		out.Items = append(out.Items, b)
	}
	return out, nil
}
