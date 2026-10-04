package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/api/client"
)

// maxAllPages bounds how many pages --all follows before giving up, so a
// server that never returns a null nextCursor cannot hang a command forever.
const maxAllPages = 100

// env carries the resolved API clients and global flags every command
// needs: cwr for the buffered ClientWithResponses methods used by nearly
// everything, raw for the unbuffered APIClient methods streaming commands
// (backup create) need directly.
type env struct {
	cwr    *client.ClientWithResponses
	raw    *client.APIClient
	json   bool
	org    string
	stdout io.Writer
	stderr io.Writer
}

// run is cfctl's entry point, called from main with the real process
// environment.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runWithEnv(ctx, args, stdout, stderr, os.Getenv)
}

// runWithEnv is run with getenv injected, so config-precedence tests never
// touch the real process environment.
func runWithEnv(ctx context.Context, args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	fs := flag.NewFlagSet("cfctl", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	urlFlag := fs.String("url", "", "server URL")
	tokenFlag := fs.String("token", "", "API bearer token")
	orgFlag := fs.String("org", "", "org id or slug (required by most commands)")
	jsonFlag := fs.Bool("json", false, "print raw server JSON instead of a table")
	timeoutFlag := fs.Duration("timeout", 30*time.Second, "request timeout")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			usage(stdout)
			return 0
		}
		fmt.Fprintf(stderr, "cfctl: %v\n", err)
		return 2
	}

	rest := fs.Args()
	if len(rest) == 0 {
		usage(stderr)
		return 2
	}
	if rest[0] == "help" {
		usage(stdout)
		return 0
	}
	if rest[0] == "version" {
		fmt.Fprintf(stdout, "cfctl %s\n", version)
		return 0
	}

	cmd, ok := commandTable()[rest[0]]
	if !ok {
		fmt.Fprintf(stderr, "cfctl: unknown command %q\n\n", rest[0])
		usage(stderr)
		return 2
	}

	cfg, err := resolveConfig(*urlFlag, *tokenFlag, getenv)
	if err != nil {
		fmt.Fprintf(stderr, "cfctl: %v\n", err)
		return 1
	}
	if cfg.URL == "" || cfg.Token == "" {
		fmt.Fprintln(stderr, "cfctl: a server URL and token are required (--url/--token, CFCTL_URL/CFCTL_TOKEN, or the config file)")
		return 2
	}

	cwr, raw, err := newClients(cfg, *timeoutFlag)
	if err != nil {
		fmt.Fprintf(stderr, "cfctl: %v\n", err)
		return 1
	}

	e := &env{cwr: cwr, raw: raw, json: *jsonFlag, org: *orgFlag, stdout: stdout, stderr: stderr}
	return cmd(ctx, e, rest[1:])
}

// newClients builds the buffered and raw clients over the same server and
// bearer-token request editor. The token is set only here, as an
// Authorization header on outgoing requests; it never appears in any
// value cfctl prints or logs.
//
// The generated client (api/oapi-codegen.client.yaml) builds every request
// path relative to the server argument it is given, exactly as declared
// under the spec's own `servers: [{url: /api/v1}]` entry — it never adds
// that prefix itself (docs/cfctl.md documents --url/CFCTL_URL as the
// server's bare base URL, for example "https://certforge.example.com",
// the same address the web UI's own origin uses), so apiBase appends it
// here, once, for both clients.
//
// hc deliberately carries no http.Client.Timeout: that bounds the whole
// round trip including reading the response body, which would cut off
// "backup create" and "certs download" partway through any archive or
// bundle that legitimately takes longer than --timeout to stream (batch-5
// review). timeout instead bounds only connecting (net.Dialer) and the
// wait for response headers (Transport.ResponseHeaderTimeout) — once
// headers arrive, the body itself has no deadline, matching the
// documented --timeout as "per-request timeout" in the sense every other
// cfctl command means it (a small JSON response's body follows its
// headers immediately either way).
func newClients(cfg Config, timeout time.Duration) (*client.ClientWithResponses, *client.APIClient, error) {
	hc := &http.Client{Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: timeout}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}}
	auth := client.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
		return nil
	})
	base := apiBase(cfg.URL)
	cwr, err := client.NewClientWithResponses(base, client.WithHTTPClient(hc), auth)
	if err != nil {
		return nil, nil, err
	}
	raw, err := client.NewClient(base, client.WithHTTPClient(hc), auth)
	if err != nil {
		return nil, nil, err
	}
	return cwr, raw, nil
}

// apiBase turns a server's bare base URL into the /api/v1 base the
// generated client's request builders resolve every operation path
// against.
func apiBase(url string) string {
	return strings.TrimRight(url, "/") + "/api/v1"
}

// commandTable maps a top-level command name to its handler. Every
// handler receives the args after its own name (e.g. "list", "<id>" for
// "certs list <id>").
func commandTable() map[string]func(context.Context, *env, []string) int {
	return map[string]func(context.Context, *env, []string) int{
		"status":   cmdStatus,
		"certs":    cmdCerts,
		"clients":  cmdClients,
		"channels": cmdChannels,
		"monitors": cmdMonitors,
		"events":   cmdEvents,
		"keys":     cmdKeys,
		"backup":   cmdBackup,
		"audit":    cmdAudit,
	}
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: cfctl [--url URL] [--token TOKEN] [--org ID|SLUG] [--json] [--timeout DURATION] <command> [args]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  status                    Server version")
	fmt.Fprintln(w, "  certs list|get|renew|download")
	fmt.Fprintln(w, "  clients list|get")
	fmt.Fprintln(w, "  channels list|test <id>")
	fmt.Fprintln(w, "  monitors list|check <id>")
	fmt.Fprintln(w, "  events list")
	fmt.Fprintln(w, "  keys status|rewrap")
	fmt.Fprintln(w, "  backup create --out <path|->")
	fmt.Fprintln(w, "  audit list")
	fmt.Fprintln(w, "  version                   Print cfctl's own build version")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Config: CFCTL_URL/CFCTL_TOKEN env vars, or $XDG_CONFIG_HOME/cfctl/config.json (mode 0600). See docs/cfctl.md.")
}

// resolveOrg resolves --org to an org id: a value that parses as a UUID is
// used directly; anything else is looked up by slug via listOrgs.
func (e *env) resolveOrg(ctx context.Context) (uuid.UUID, error) {
	if e.org == "" {
		return uuid.Nil, errors.New("--org is required")
	}
	if id, err := uuid.Parse(e.org); err == nil {
		return id, nil
	}
	resp, err := e.cwr.ListOrgsWithResponse(ctx)
	if err != nil {
		return uuid.Nil, err
	}
	if err := e.checkStatus(resp.StatusCode(), resp.Body, http.StatusOK); err != nil {
		return uuid.Nil, err
	}
	if resp.JSON200 == nil {
		return uuid.Nil, errNonJSON
	}
	for _, o := range resp.JSON200.Items {
		if o.Slug == e.org {
			return o.Id, nil
		}
	}
	return uuid.Nil, fmt.Errorf("no org with id or slug %q", e.org)
}

// errNonJSON is returned when a success status carries a body the generated
// client did not decode as JSON (JSON200 is nil), such as a proxy's HTML page.
var errNonJSON = errors.New("unexpected non-JSON response from server")

// checkStatus echoes body under --json (cfctl's raw output mode, on
// success or failure alike) and turns a status outside ok into a
// *problemError.
func (e *env) checkStatus(status int, body []byte, ok ...int) error {
	if e.json {
		_, _ = e.stdout.Write(body)
		fmt.Fprintln(e.stdout)
	}
	for _, s := range ok {
		if status == s {
			return nil
		}
	}
	return problemFromBody(status, body)
}

// fetchPages drives cursor pagination: fetch is called once per page and
// must return that page's status, raw body and nextCursor, appending its
// own rows (closed over by the caller) as a side effect before returning.
// Pagination continues while all is true and the server still returns a
// cursor, bounded by maxAllPages.
func (e *env) fetchPages(all bool, cursor string, fetch func(cursor string) (status int, body []byte, next *string, err error)) error {
	cur := cursor
	for i := 0; i < maxAllPages; i++ {
		status, body, next, err := fetch(cur)
		if err != nil {
			return err
		}
		if err := e.checkStatus(status, body, http.StatusOK); err != nil {
			return err
		}
		if !all || next == nil || *next == "" {
			return nil
		}
		cur = *next
	}
	return fmt.Errorf("--all stopped after %d pages", maxAllPages)
}

// usageErr reports a flag-parsing error and returns exit code 2.
func usageErr(stderr io.Writer, err error) int {
	fmt.Fprintf(stderr, "cfctl: %v\n", err)
	return 2
}

// strPtr returns nil for an empty string, so an optional query parameter
// is omitted from the request rather than sent as "".
func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// parseTimeFlag parses a --since value as RFC 3339.
func parseTimeFlag(s string) (time.Time, error) {
	return time.Parse(time.RFC3339, s)
}
