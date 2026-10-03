package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime/multipart"
	"net/http"
	"time"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/importer"
	"github.com/metril/certforge/internal/issuance"
)

// ImportCertificates previews (dryRun, the default) or stores every
// certificate found in an acme.sh or certbot archive. The request body is
// multipart/form-data (router.go's requireJSON enforces that, and caps it
// at 32 MiB, for exactly this route); the strict server hands the handler
// the raw *multipart.Reader instead of a decoded struct, so this file
// parses the three fields (archive, caId, dryRun) itself. Needs
// certs:write.
func (s *Server) ImportCertificates(ctx context.Context, r gen.ImportCertificatesRequestObject) (gen.ImportCertificatesResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionCertsWrite, &r.OrgId); err != nil {
		return nil, err
	}
	// A 32 MiB upload can outlast the server's ReadTimeout; only a caller
	// who passed authn, requireJSON's multipart check and authorize gets
	// longer (the error is http.ErrNotSupported for a writer that cannot,
	// which keeps the server default).
	if w, _ := httpFrom(ctx); w != nil {
		_ = http.NewResponseController(w).SetReadDeadline(time.Now().Add(importReadTimeout))
	}
	fsys, caID, dryRun, err := parseImportMultipart(r.Body)
	if err != nil {
		return nil, err
	}
	result, err := s.d.Issuance.ImportCertificates(ctx, r.OrgId, caID, fsys, dryRun)
	if err != nil {
		return nil, mapErr(err)
	}
	return gen.ImportCertificates200JSONResponse(importResultOut(result)), nil
}

// parseImportMultipart reads every part of body: archive (extracted with
// importer.ExtractArchive as it streams by, so a too-large or malformed
// archive is caught here rather than buffered first), caId (a uuid),
// dryRun (a bool, defaulting to true — the OpenAPI default — when the
// field is absent). A read that outgrows requireJSON's 32 MiB
// MaxBytesReader surfaces here as *http.MaxBytesError (the strict server's
// own decoding, r.MultipartReader(), only parses headers, so it never sees
// this), which is where importCertificates' 413 comes from.
func parseImportMultipart(body *multipart.Reader) (fs.FS, uuid.UUID, bool, error) {
	var fsys fs.FS
	var caID uuid.UUID
	dryRun, haveArchive, haveCA := true, false, false
	for {
		part, err := body.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, uuid.Nil, false, mapMultipartErr(err)
		}
		switch part.FormName() {
		case "archive":
			fsys, err = importer.ExtractArchive(part)
			_ = part.Close()
			if err != nil {
				// A too-large read surfaces from inside ExtractArchive
				// (io.ReadAll over the MaxBytesReader-wrapped body), and
				// ExtractArchive itself wraps it as ErrArchive too (an
				// oversized archive IS an invalid one) — so the size limit
				// is checked first, or every over-budget upload would
				// report 422 instead of 413.
				var mbe *http.MaxBytesError
				if errors.As(err, &mbe) {
					return nil, uuid.Nil, false, mapMultipartErr(err)
				}
				if errors.Is(err, importer.ErrArchive) {
					return nil, uuid.Nil, false, unprocessable("archive", err.Error())
				}
				return nil, uuid.Nil, false, mapMultipartErr(err)
			}
			haveArchive = true
		case "caId":
			b, rerr := io.ReadAll(part)
			_ = part.Close()
			if rerr != nil {
				return nil, uuid.Nil, false, mapMultipartErr(rerr)
			}
			id, perr := uuid.Parse(strings.TrimSpace(string(b)))
			if perr != nil {
				return nil, uuid.Nil, false, unprocessable("caId", "must be a uuid")
			}
			caID, haveCA = id, true
		case "dryRun":
			b, rerr := io.ReadAll(part)
			_ = part.Close()
			if rerr != nil {
				return nil, uuid.Nil, false, mapMultipartErr(rerr)
			}
			v, perr := strconv.ParseBool(strings.TrimSpace(string(b)))
			if perr != nil {
				return nil, uuid.Nil, false, unprocessable("dryRun", "must be a boolean")
			}
			dryRun = v
		default:
			_ = part.Close()
		}
	}
	if !haveArchive {
		return nil, uuid.Nil, false, unprocessable("archive", "required")
	}
	if !haveCA {
		return nil, uuid.Nil, false, unprocessable("caId", "required")
	}
	return fsys, caID, dryRun, nil
}

// mapMultipartErr mirrors requestError (problem.go) for an error surfacing
// from inside the handler instead of from the strict server's own
// decoding: a body that outgrew the MaxBytesReader is 413, anything else
// reading the multipart body is 400.
func mapMultipartErr(err error) error {
	var mbe *http.MaxBytesError
	if errors.As(err, &mbe) {
		return &HTTPError{Status: http.StatusRequestEntityTooLarge, Title: "Payload too large",
			Detail: fmt.Sprintf("Request body must not exceed %d bytes.", mbe.Limit)}
	}
	return &HTTPError{Status: http.StatusBadRequest, Title: "Bad request", Detail: err.Error()}
}

func importResultOut(r issuance.ImportResult) gen.ImportResult {
	items := make([]gen.ImportItem, len(r.Items))
	for i, it := range r.Items {
		items[i] = gen.ImportItem{Name: it.Name, Names: it.Names, NotAfter: it.NotAfter, Issuer: it.Issuer,
			HasKey: it.HasKey, Source: gen.ImportSource(it.Source), Action: gen.ImportAction(it.Action),
			Reason: it.Reason, CertificateId: it.CertificateID}
	}
	return gen.ImportResult{DryRun: r.DryRun, Items: items}
}
