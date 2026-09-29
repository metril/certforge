package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/client"
)

func cmdCerts(ctx context.Context, e *env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(e.stderr, "cfctl certs: expected a subcommand (list, get, renew, download)")
		return 2
	}
	switch args[0] {
	case "list":
		return certsList(ctx, e, args[1:])
	case "get":
		return certsGet(ctx, e, args[1:])
	case "renew":
		return certsRenew(ctx, e, args[1:])
	case "download":
		return certsDownload(ctx, e, args[1:])
	default:
		fmt.Fprintf(e.stderr, "cfctl certs: unknown subcommand %q\n", args[0])
		return 2
	}
}

// certsList lists certificates. Without --org it lists across every org
// the caller can read (listAllCertificates); with --org it lists that
// org's certificates (listCertificates).
func certsList(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("certs list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	status := fs.String("status", "", "filter by status")
	cursor := fs.String("cursor", "", "page cursor")
	all := fs.Bool("all", false, "follow every page (nextCursor), up to 100 pages")
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}

	var rows [][]string
	err := e.fetchPages(*all, *cursor, func(cur string) (int, []byte, *string, error) {
		if e.org == "" {
			params := &client.ListAllCertificatesParams{Cursor: strPtr(cur)}
			if *status != "" {
				s := client.ListAllCertificatesParamsStatus(*status)
				params.Status = &s
			}
			resp, err := e.cwr.ListAllCertificatesWithResponse(ctx, params)
			if err != nil {
				return 0, nil, nil, err
			}
			if resp.JSON200 != nil {
				for _, c := range resp.JSON200.Items {
					rows = append(rows, certRow(c))
				}
				return resp.StatusCode(), resp.Body, resp.JSON200.NextCursor, nil
			}
			return resp.StatusCode(), resp.Body, nil, nil
		}
		orgID, err := e.resolveOrg(ctx)
		if err != nil {
			return 0, nil, nil, err
		}
		params := &client.ListCertificatesParams{Cursor: strPtr(cur)}
		if *status != "" {
			s := client.ListCertificatesParamsStatus(*status)
			params.Status = &s
		}
		resp, err := e.cwr.ListCertificatesWithResponse(ctx, orgID, params)
		if err != nil {
			return 0, nil, nil, err
		}
		if resp.JSON200 != nil {
			for _, c := range resp.JSON200.Items {
				rows = append(rows, certRow(c))
			}
			return resp.StatusCode(), resp.Body, resp.JSON200.NextCursor, nil
		}
		return resp.StatusCode(), resp.Body, nil, nil
	})
	if err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		writeTable(e.stdout, []string{"ID", "NAME", "STATUS", "NOT AFTER"}, rows)
	}
	return 0
}

func certRow(c client.Certificate) []string {
	return []string{c.Id.String(), c.Name, string(c.Status), notAfterOf(c)}
}

func notAfterOf(c client.Certificate) string {
	if c.CurrentVersion == nil {
		return "-"
	}
	return c.CurrentVersion.NotAfter.Format(timeFormat)
}

func certsGet(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("certs get", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(e.stderr, "cfctl certs get: expected exactly one certificate id")
		return 2
	}
	id, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(e.stderr, "cfctl: invalid certificate id: %v\n", err)
		return 2
	}
	orgID, err := e.resolveOrg(ctx)
	if err != nil {
		return fail(e.stderr, err)
	}
	resp, err := e.cwr.GetCertificateWithResponse(ctx, orgID, id)
	if err != nil {
		return fail(e.stderr, err)
	}
	if err := e.checkStatus(resp.StatusCode(), resp.Body, http.StatusOK); err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		c := *resp.JSON200
		writeTable(e.stdout, []string{"FIELD", "VALUE"}, [][]string{
			{"id", c.Id.String()},
			{"name", c.Name},
			{"commonName", c.CommonName},
			{"status", string(c.Status)},
			{"managed", fmt.Sprintf("%t", c.Managed)},
			{"notAfter", notAfterOf(c)},
		})
	}
	return 0
}

func certsRenew(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("certs renew", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(e.stderr, "cfctl certs renew: expected exactly one certificate id")
		return 2
	}
	id, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(e.stderr, "cfctl: invalid certificate id: %v\n", err)
		return 2
	}
	orgID, err := e.resolveOrg(ctx)
	if err != nil {
		return fail(e.stderr, err)
	}
	resp, err := e.cwr.RenewCertificateWithResponse(ctx, orgID, id)
	if err != nil {
		return fail(e.stderr, err)
	}
	if err := e.checkStatus(resp.StatusCode(), resp.Body, http.StatusAccepted); err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		fmt.Fprintf(e.stdout, "enqueued=%t\n", resp.JSON202.Enqueued)
	}
	return 0
}

// certsDownload picks the certificate's currentVersionId unless --version
// is given, then downloads that version's parts to --out (0600) or, with
// "-" (the default), stdout.
func certsDownload(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("certs download", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	version := fs.String("version", "", "version id; defaults to the certificate's current version")
	format := fs.String("format", "pem", "pem or der")
	parts := fs.String("parts", "fullchain,key", "comma-separated parts (cert, chain, fullchain, key, combined)")
	out := fs.String("out", "-", "output path, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(e.stderr, "cfctl certs download: expected exactly one certificate id")
		return 2
	}
	certID, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(e.stderr, "cfctl: invalid certificate id: %v\n", err)
		return 2
	}
	orgID, err := e.resolveOrg(ctx)
	if err != nil {
		return fail(e.stderr, err)
	}

	versionID := *version
	if versionID == "" {
		certResp, err := e.cwr.GetCertificateWithResponse(ctx, orgID, certID)
		if err != nil {
			return fail(e.stderr, err)
		}
		if certResp.StatusCode() != http.StatusOK || certResp.JSON200 == nil {
			return fail(e.stderr, problemFromBody(certResp.StatusCode(), certResp.Body))
		}
		if certResp.JSON200.CurrentVersion == nil {
			fmt.Fprintln(e.stderr, "cfctl: certificate has no current version")
			return 1
		}
		versionID = certResp.JSON200.CurrentVersion.Id.String()
	}
	vid, err := uuid.Parse(versionID)
	if err != nil {
		fmt.Fprintf(e.stderr, "cfctl: invalid version id: %v\n", err)
		return 2
	}

	params := &client.DownloadCertificateVersionParams{Parts: *parts}
	if *format != "" {
		f := client.DownloadCertificateVersionParamsFormat(*format)
		params.Format = &f
	}
	resp, err := e.cwr.DownloadCertificateVersionWithResponse(ctx, orgID, certID, vid, params)
	if err != nil {
		return fail(e.stderr, err)
	}
	if resp.StatusCode() != http.StatusOK {
		return fail(e.stderr, problemFromBody(resp.StatusCode(), resp.Body))
	}
	if *out == "-" {
		_, _ = e.stdout.Write(resp.Body)
		return 0
	}
	if err := writeFileAtomic(*out, resp.Body); err != nil {
		fmt.Fprintf(e.stderr, "cfctl: %v\n", err)
		return 1
	}
	fmt.Fprintf(e.stdout, "wrote %s (%d bytes)\n", *out, len(resp.Body))
	return 0
}
