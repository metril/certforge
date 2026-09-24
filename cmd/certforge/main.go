// Command certforge is the CertForge server binary.
package main

import (
	"context"
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
	}
}

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
