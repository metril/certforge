# 0019: cfctl built on the generated API client, no CLI framework

Status: accepted (Phase 6A)

## Context

`cfctl` (Task 13) is a small operator CLI: check status, list and act on
certificates, clients, notification channels, external monitors, events,
KEK status, an on-demand backup, and the audit log, all against a running
server's REST API. Two decisions shape it: what talks to the server, and
what parses the command line.

For the server call, Task 2 already generates `internal/api/client`
(`ClientWithResponses`/`NewClientWithResponses`, `WithRequestEditorFn`)
straight from `api/openapi.yaml` for exactly this purpose (Deviations R1).
Hand-writing request/response structs a second time in `cmd/cfctl` would
immediately drift from the spec — a field rename or a new required
parameter would compile against a stale shape instead of failing to build.

For the command line, CertForge's other binaries (`cmd/certforge`,
`cmd/certforge-agent`) already use a flat `command` table over
`flag.FlagSet`, no framework, so a `run(ctx, args, stdout, stderr) int`
entry point stays trivially testable by construction.

## Decision

- **`cfctl` talks to the server only through `internal/api/client`.** Most
  commands use `ClientWithResponses`, whose methods return a typed
  `Response` with a buffered `Body []byte` and one `JSON2xx` field per
  success shape; `cfctl` never re-declares request or response JSON itself.
  `backup create` is the one exception: it calls the raw `APIClient`'s
  `CreateBackup` directly, which returns an unbuffered `*http.Response`,
  because a multi-gigabyte archive must stream straight through
  `io.Copy`, never sitting fully in `cfctl`'s memory the way
  `ClientWithResponses` would force it to.
- **Every response's problem body is parsed generically, not per status
  code.** oapi-codegen gives each response struct one field per declared
  error status (`ApplicationproblemJSON401 *Unauthorized`,
  `...JSON404 *NotFound`, and so on), but every one of those named types
  is a plain alias for `client.Problem`. Rather than switch on which
  field is set, `cfctl` unmarshals `resp.Body` into a `client.Problem`
  directly whenever `resp.StatusCode()` is not the expected success code,
  and renders it as `error: <title>: <detail>` (`problemFromBody`,
  `output.go`). This is the only shape that stays correct automatically
  as new error responses are added to the spec.
- **No CLI framework; a `command` table over `flag.FlagSet`, matching
  `cmd/certforge`.** Global flags (`--url`, `--token`, `--org`, `--json`,
  `--timeout`) are parsed once by a top-level `flag.FlagSet`; each
  resource command (`certs`, `clients`, `channels`, `monitors`, `events`,
  `keys`, `backup`, `audit`) dispatches to a verb (`list`, `get`, …) with
  its own `flag.FlagSet` for command-specific flags. `run` stays a pure
  function of `(ctx, args, stdout, stderr) int`, so every test drives it
  (or the individual command functions) directly against an
  `httptest.Server`, with no process boundary, global state, or
  `os.Exit` in the code under test.
- **`--org` accepts a slug and resolves it through `listOrgs`.** Every
  org-scoped operation's path parameter is a UUID, but a human typing
  `cfctl --org acme certs list` should not have to look one up first.
  `env.resolveOrg` parses `--org` as a UUID first (the common case in
  scripts) and falls back to a `listOrgs` call matching on `slug`
  otherwise — a single extra round trip, and cached per invocation since
  `cfctl` is a one-shot command, not a long-running process.
- **The token lives only in a `WithRequestEditorFn` closure.** It is set
  once, as the `Authorization: Bearer <token>` header on outgoing
  requests, and captured by the closure the client construction returns;
  it is never assigned to a struct field `cfctl` might accidentally print,
  logged, or embedded in an error string (a network error names the host
  and port, never the header). `docs/cfctl.md#config` still warns that
  `--token` on the command line is visible in `ps` output from other
  users on the same host, and recommends `CFCTL_TOKEN` or the config file
  instead.

## Consequences

- A spec change that adds, renames, or retypes a field is caught at
  `cfctl`'s own `go build` the moment `make generate` regenerates
  `internal/api/client`, the same guarantee the server side already has
  from its generated strict server.
- `cfctl` cannot do anything the OpenAPI spec does not expose (no
  raw-SQL escape hatches, no direct database access) — a deliberate
  boundary: an operator's automation goes through the same authorization
  and audit path a browser session would.
- The config file (`$XDG_CONFIG_HOME/cfctl/config.json`) is refused
  outright if its mode grants any group or other permission bit, the same
  posture CertForge takes with the KEK and root secret elsewhere: a
  credential at rest is either provably private or not accepted at all.
