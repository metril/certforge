package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/client"
)

// --- status ---

func cmdStatus(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}
	resp, err := e.cwr.GetServerInfoWithResponse(ctx)
	if err != nil {
		return fail(e.stderr, err)
	}
	if err := e.checkStatus(resp.StatusCode(), resp.Body, http.StatusOK); err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		if resp.JSON200 == nil {
			return fail(e.stderr, errNonJSON)
		}
		writeTable(e.stdout, []string{"FIELD", "VALUE"}, [][]string{
			{"version", resp.JSON200.Version},
		})
	}
	return 0
}

// --- clients ---

func cmdClients(ctx context.Context, e *env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(e.stderr, "cfctl clients: expected a subcommand (list, get)")
		return 2
	}
	switch args[0] {
	case "list":
		return clientsList(ctx, e, args[1:])
	case "get":
		return clientsGet(ctx, e, args[1:])
	default:
		fmt.Fprintf(e.stderr, "cfctl clients: unknown subcommand %q\n", args[0])
		return 2
	}
}

// clientsList lists clients. Without --org it lists across every org the
// caller can read (listAllClients); with --org it lists that org's
// clients (listClients).
func clientsList(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("clients list", flag.ContinueOnError)
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
			params := &client.ListAllClientsParams{Cursor: strPtr(cur)}
			if *status != "" {
				s := client.ClientStatusFilter(*status)
				params.Status = &s
			}
			resp, err := e.cwr.ListAllClientsWithResponse(ctx, params)
			if err != nil {
				return 0, nil, nil, err
			}
			if resp.JSON200 != nil {
				for _, c := range resp.JSON200.Items {
					rows = append(rows, clientRow(c))
				}
				return resp.StatusCode(), resp.Body, resp.JSON200.NextCursor, nil
			}
			return resp.StatusCode(), resp.Body, nil, nil
		}
		orgID, err := e.resolveOrg(ctx)
		if err != nil {
			return 0, nil, nil, err
		}
		params := &client.ListClientsParams{Cursor: strPtr(cur)}
		if *status != "" {
			s := client.ClientStatusFilter(*status)
			params.Status = &s
		}
		resp, err := e.cwr.ListClientsWithResponse(ctx, orgID, params)
		if err != nil {
			return 0, nil, nil, err
		}
		if resp.JSON200 != nil {
			for _, c := range resp.JSON200.Items {
				rows = append(rows, clientRow(c))
			}
			return resp.StatusCode(), resp.Body, resp.JSON200.NextCursor, nil
		}
		return resp.StatusCode(), resp.Body, nil, nil
	})
	if err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		writeTable(e.stdout, []string{"ID", "NAME", "STATUS", "ONLINE"}, rows)
	}
	return 0
}

func clientRow(c client.Client) []string {
	return []string{c.Id.String(), c.Name, string(c.Status), fmt.Sprintf("%t", c.Online)}
}

func clientsGet(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("clients get", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(e.stderr, "cfctl clients get: expected exactly one client id")
		return 2
	}
	id, err := uuid.Parse(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(e.stderr, "cfctl: invalid client id: %v\n", err)
		return 2
	}
	orgID, err := e.resolveOrg(ctx)
	if err != nil {
		return fail(e.stderr, err)
	}
	resp, err := e.cwr.GetClientWithResponse(ctx, orgID, id)
	if err != nil {
		return fail(e.stderr, err)
	}
	if err := e.checkStatus(resp.StatusCode(), resp.Body, http.StatusOK); err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		if resp.JSON200 == nil {
			return fail(e.stderr, errNonJSON)
		}
		c := *resp.JSON200
		writeTable(e.stdout, []string{"FIELD", "VALUE"}, [][]string{
			{"id", c.Id.String()},
			{"name", c.Name},
			{"status", string(c.Status)},
			{"online", fmt.Sprintf("%t", c.Online)},
			{"hostname", c.Hostname},
		})
	}
	return 0
}

// --- keys ---

func cmdKeys(ctx context.Context, e *env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(e.stderr, "cfctl keys: expected a subcommand (status, rewrap)")
		return 2
	}
	switch args[0] {
	case "status":
		return keysStatus(ctx, e, args[1:])
	case "rewrap":
		return keysRewrap(ctx, e, args[1:])
	default:
		fmt.Fprintf(e.stderr, "cfctl keys: unknown subcommand %q\n", args[0])
		return 2
	}
}

func keysStatus(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("keys status", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}
	resp, err := e.cwr.GetKeysStatusWithResponse(ctx)
	if err != nil {
		return fail(e.stderr, err)
	}
	if err := e.checkStatus(resp.StatusCode(), resp.Body, http.StatusOK); err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		if resp.JSON200 == nil {
			return fail(e.stderr, errNonJSON)
		}
		writeTable(e.stdout, []string{"FIELD", "VALUE"}, keysStatusRows(*resp.JSON200))
	}
	return 0
}

func keysStatusRows(k client.KeysStatus) [][]string {
	running := "false"
	remaining := "-"
	if k.Rewrap != nil {
		running = fmt.Sprintf("%t", k.Rewrap.Running)
		remaining = fmt.Sprintf("%d", k.Rewrap.Remaining)
	}
	return [][]string{
		{"kekId", k.KekId},
		{"kind", string(k.Kind)},
		{"canaryOk", fmt.Sprintf("%t", k.CanaryOk)},
		{"rewrapRunning", running},
		{"rewrapRemaining", remaining},
	}
}

func keysRewrap(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("keys rewrap", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}
	resp, err := e.cwr.StartRewrapWithResponse(ctx)
	if err != nil {
		return fail(e.stderr, err)
	}
	if err := e.checkStatus(resp.StatusCode(), resp.Body, http.StatusAccepted); err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		if resp.JSON202 == nil {
			return fail(e.stderr, errNonJSON)
		}
		writeTable(e.stdout, []string{"FIELD", "VALUE"}, keysStatusRows(*resp.JSON202))
	}
	return 0
}

// --- backup ---

func cmdBackup(ctx context.Context, e *env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(e.stderr, "cfctl backup: expected a subcommand (create)")
		return 2
	}
	switch args[0] {
	case "create":
		return backupCreate(ctx, e, args[1:])
	default:
		fmt.Fprintf(e.stderr, "cfctl backup: unknown subcommand %q\n", args[0])
		return 2
	}
}

// backupCreate streams GET /backup straight to --out, using the raw
// (unbuffered) API client: ClientWithResponses reads the whole body into
// memory before returning, which a multi-gigabyte database archive must
// not do. The archive is written to a 0600 temp file beside --out and
// renamed onto it only once the whole stream has copied successfully; a
// failure removes the temp file rather than leaving a partial archive.
// "-" streams straight to stdout instead.
func backupCreate(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("backup create", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("out", "", "output archive path, or - for stdout")
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}
	if *out == "" {
		fmt.Fprintln(e.stderr, "cfctl backup create: --out is required")
		return 2
	}

	resp, err := e.raw.CreateBackup(ctx)
	if err != nil {
		return fail(e.stderr, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		return fail(e.stderr, problemFromBody(resp.StatusCode, body))
	}

	if *out == "-" {
		if _, err := io.Copy(e.stdout, resp.Body); err != nil {
			fmt.Fprintf(e.stderr, "cfctl: %v\n", err)
			return 1
		}
		return 0
	}

	tmp, err := os.CreateTemp(filepath.Dir(*out), ".cfctl-backup-*.tmp")
	if err != nil {
		fmt.Fprintf(e.stderr, "cfctl: %v\n", err)
		return 1
	}
	tmpPath := tmp.Name()
	n, err := io.Copy(tmp, resp.Body)
	if err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		fmt.Fprintf(e.stderr, "cfctl: %v\n", err)
		return 1
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		fmt.Fprintf(e.stderr, "cfctl: %v\n", err)
		return 1
	}
	if err := os.Rename(tmpPath, *out); err != nil {
		_ = os.Remove(tmpPath)
		fmt.Fprintf(e.stderr, "cfctl: %v\n", err)
		return 1
	}
	fmt.Fprintf(e.stdout, "backup written to %s (%d bytes)\n", *out, n)
	return 0
}

// --- audit ---

func cmdAudit(ctx context.Context, e *env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(e.stderr, "cfctl audit: expected a subcommand (list)")
		return 2
	}
	switch args[0] {
	case "list":
		return auditList(ctx, e, args[1:])
	default:
		fmt.Fprintf(e.stderr, "cfctl audit: unknown subcommand %q\n", args[0])
		return 2
	}
}

func auditList(ctx context.Context, e *env, args []string) int {
	fs := flag.NewFlagSet("audit list", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	action := fs.String("action", "", "exact action, or a prefix ending in a dot")
	cursor := fs.String("cursor", "", "page cursor")
	all := fs.Bool("all", false, "follow every page (nextCursor), up to 100 pages")
	if err := fs.Parse(args); err != nil {
		return usageErr(e.stderr, err)
	}

	var rows [][]string
	err := e.fetchPages(*all, *cursor, func(cur string) (int, []byte, *string, error) {
		params := &client.ListAuditEventsParams{Cursor: strPtr(cur), Action: strPtr(*action)}
		resp, err := e.cwr.ListAuditEventsWithResponse(ctx, params)
		if err != nil {
			return 0, nil, nil, err
		}
		if resp.JSON200 != nil {
			for _, ev := range resp.JSON200.Items {
				rows = append(rows, []string{
					fmt.Sprintf("%d", ev.Id), ev.Action, ev.ActorName, ev.Ts.Format(timeFormat), ev.ResourceType, ev.ResourceId,
				})
			}
			return resp.StatusCode(), resp.Body, resp.JSON200.NextCursor, nil
		}
		return resp.StatusCode(), resp.Body, nil, nil
	})
	if err != nil {
		return fail(e.stderr, err)
	}
	if !e.json {
		writeTable(e.stdout, []string{"ID", "ACTION", "ACTOR", "TS", "RESOURCE TYPE", "RESOURCE ID"}, rows)
	}
	return 0
}
