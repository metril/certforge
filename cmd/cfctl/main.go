// Command cfctl is the CertForge operator CLI: a thin stdlib-only client
// over the generated api/client (Task 2) for scripting and ad hoc
// operations against a running server (status, certificates, clients,
// notification channels, external monitors, events, KEK status/rewrap,
// on-demand backup, and the audit log). See docs/cfctl.md.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}
