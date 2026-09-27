package api

import (
	"context"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/issuance"
)

// uploadInputFrom builds an issuance.UploadInput from the optional fields
// CertificateUpload and CertificateVersionUpload share.
func uploadInputFrom(certPEM, keyPEM *string, p12 *[]byte, password *string) issuance.UploadInput {
	in := issuance.UploadInput{}
	if certPEM != nil {
		in.CertificatePEM = []byte(*certPEM)
	}
	if keyPEM != nil {
		in.PrivateKeyPEM = []byte(*keyPEM)
	}
	if p12 != nil {
		in.PKCS12 = *p12
	}
	if password != nil {
		in.Password = *password
	}
	return in
}

// UploadCertificate stores an existing certificate (PEM leaf, optionally
// followed by its chain, plus an optional key; or a PKCS#12 bundle) as a
// new unmanaged certificate: managed false, no CA, nextRenewAt null, status
// from the leaf's own validity. Needs certs:write.
func (s *Server) UploadCertificate(ctx context.Context, r gen.UploadCertificateRequestObject) (gen.UploadCertificateResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	in := uploadInputFrom(r.Body.CertificatePem, r.Body.PrivateKeyPem, r.Body.Pkcs12Base64, r.Body.Password)
	c, _, err := s.d.Issuance.UploadCertificate(ctx, r.OrgId, r.Body.Name, in)
	if err != nil {
		return nil, mapErr(err)
	}
	o, err := s.certOut(ctx, c)
	if err != nil {
		return nil, err
	}
	return gen.UploadCertificate201JSONResponse(o), nil
}

// UploadCertificateVersion adds an uploaded version to an existing
// unmanaged certificate; 409 when the certificate is managed. A keyless
// upload is refused (409) when the certificate has a live grant whose
// layout or deploy target needs a key — checked here, before the write,
// since internal/issuance must not import internal/agents (R7) to check it
// itself. The managed check is read here first (before the agents.Service
// call) so a managed certificate's upload never needs the agents
// dependency at all — it fails the same way issuance.Service.UploadVersion
// would fail it anyway, just without touching grants for a certificate
// that was never going to accept the version. Needs certs:write.
func (s *Server) UploadCertificateVersion(ctx context.Context, r gen.UploadCertificateVersionRequestObject) (gen.UploadCertificateVersionResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	cur, err := s.d.Issuance.Store.GetCertificate(ctx, r.OrgId, r.Id)
	if err != nil {
		return nil, mapErr(err)
	}
	in := uploadInputFrom(r.Body.CertificatePem, r.Body.PrivateKeyPem, r.Body.Pkcs12Base64, r.Body.Password)
	if !cur.Managed {
		issued, _, err := issuance.ParseUpload(in)
		if err != nil {
			return nil, mapErr(err)
		}
		if len(issued.PrivateKeyPKCS8) == 0 {
			needsKey, err := s.d.Agents.LiveGrantsNeedKey(ctx, r.Id)
			if err != nil {
				return nil, err
			}
			if needsKey {
				return nil, conflict("This certificate has a live grant whose layout or deploy target needs a key; upload a version with a key, or remove those grants first.")
			}
		}
	}
	_, v, err := s.d.Issuance.UploadVersion(ctx, r.OrgId, r.Id, in)
	if err != nil {
		return nil, mapErr(err)
	}
	return gen.UploadCertificateVersion201JSONResponse(versionOut(v)), nil
}
