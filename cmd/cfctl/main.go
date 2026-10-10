// Command cfctl is the CertForge operator CLI: a thin stdlib-only client
// over the generated api/client (Task 2) for scripting and ad hoc
// operations against a running server (status, certificates, clients,
// notification channels, external monitors, events, KEK status/rewrap,
// on-demand backup, and the audit log). See docs/reference/cfctl.md.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

// version is stamped by the Makefile's build target
// (-X main.version=$(VERSION)); "dev" otherwise.
var version = "dev"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
