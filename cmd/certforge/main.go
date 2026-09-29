// Command certforge is the CertForge server binary.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
)

var version = "dev"

type command struct {
	name    string
	summary string
	run     func(ctx context.Context, args []string, stdout io.Writer) error
}

func commands() []command {
	return []command{
		{name: "version", summary: "Print the version", run: runVersion},
		{name: "migrate", summary: "Apply database migrations", run: runMigrate},
		{name: "bootstrap-admin", summary: "Reset (after setup) the local admin password", run: runBootstrapAdmin},
		{name: "serve", summary: "Run the HTTP server", run: runServe},
		{name: "healthcheck", summary: "Probe /readyz on the local listener", run: runHealthcheck},
		{name: "backup", summary: "Write an encrypted backup archive", run: runBackup},
		{name: "restore", summary: "Restore an encrypted backup archive (offline only)", run: runRestore},
	}
}

// exitError lets a command exit with a code other than the default 1
// without calling os.Exit itself, so run stays testable through its
// return value. A nil err prints nothing to stderr (the command already
// reported whatever it needed to on stdout); restore's "without --yes"
// path uses this to exit 2 silently.
type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string {
	if e.err == nil {
		return fmt.Sprintf("exit %d", e.code)
	}
	return e.err.Error()
}

func (e *exitError) Unwrap() error { return e.err }

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)
	stop()
	os.Exit(code)
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		usage(stderr)
		return 2
	}
	switch args[0] {
	case "help", "-h", "--help":
		usage(stdout)
		return 0
	}
	for _, c := range commands() {
		if c.name != args[0] {
			continue
		}
		if err := c.run(ctx, args[1:], stdout); err != nil {
			var ee *exitError
			if errors.As(err, &ee) {
				if ee.err != nil {
					fmt.Fprintf(stderr, "certforge %s: %v\n", c.name, ee.err)
				}
				return ee.code
			}
			fmt.Fprintf(stderr, "certforge %s: %v\n", c.name, err)
			return 1
		}
		return 0
	}
	fmt.Fprintf(stderr, "certforge: unknown command %q\n\n", args[0])
	usage(stderr)
	return 2
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "Usage: certforge <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	for _, c := range commands() {
		fmt.Fprintf(w, "  %-16s %s\n", c.name, c.summary)
	}
}

func runVersion(_ context.Context, _ []string, stdout io.Writer) error {
	_, err := fmt.Fprintln(stdout, version)
	return err
}
