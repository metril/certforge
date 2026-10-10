// Command certforge-agent installs CertForge certificates on a host; see
// docs/reference/agent.md.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/metril/certforge/internal/agent"
)

var version = "dev"

const usage = "usage: certforge-agent run | pull | enroll --token <token> | status | version"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv)) }

func run(args []string, stdout, stderr io.Writer, getenv func(string) string) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return 2
	}
	log := slog.New(slog.NewTextHandler(stderr, nil))
	cfg, err := agent.LoadConfig(getenv, version)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch args[0] {
	case "enroll":
		fs := flag.NewFlagSet("enroll", flag.ContinueOnError)
		fs.SetOutput(stderr)
		token := fs.String("token", "", "one-time enrolment token (default: CF_AGENT_TOKEN or CF_AGENT_TOKEN_FILE)")
		if err := fs.Parse(args[1:]); err != nil {
			return 2
		}
		tok := *token
		if tok == "" {
			if tok, err = cfg.ResolveToken(); err != nil {
				fmt.Fprintln(stderr, err)
				return 2
			}
		}
		if tok == "" {
			fmt.Fprintln(stderr, "enroll: --token is required")
			return 2
		}
		id, err := agent.EnrollWith(ctx, agent.EnrollOptions{Log: log}, cfg.DataDir, tok, agent.Facts(version))
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		fmt.Fprintf(stdout, "enrolled as client %s\n", id.State.ClientID)
		return 0
	case "run":
		err = agent.Run(ctx, cfg, log)
	case "pull":
		err = agent.Pull(ctx, cfg, log)
	case "status":
		err = agent.Status(stdout, cfg.DataDir, time.Now())
	case "version":
		fmt.Fprintln(stdout, version)
		return 0
	default:
		fmt.Fprintln(stderr, usage)
		return 2
	}
	if err != nil {
		log.Error(args[0]+" failed", "err", err)
		return 1
	}
	return 0
}
