package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/db"
	"github.com/metril/certforge/internal/settings"
	"github.com/metril/certforge/internal/setup"
)

// stdin is replaceable in tests; nil means os.Stdin.
var stdin io.Reader

func runBootstrapAdmin(ctx context.Context, args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("bootstrap-admin", flag.ContinueOnError)
	fromStdin := flags.Bool("password-stdin", false, "read the new password from the first line of stdin")
	if err := flags.Parse(args); err != nil {
		return err
	}
	password := os.Getenv("CF_ADMIN_PASSWORD")
	if *fromStdin {
		in := stdin
		if in == nil {
			in = os.Stdin
		}
		line, err := bufio.NewReader(in).ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return fmt.Errorf("read password: %w", err)
		}
		password = strings.TrimRight(line, "\r\n")
	}
	if password == "" {
		return errors.New("set CF_ADMIN_PASSWORD or pass --password-stdin")
	}
	_, _, pool, err := openDeps(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	id, err := setup.New(pool, audit.New(pool), settings.DefaultRegistry()).SetAdminPassword(ctx, password)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "local admin %s: password set, existing sessions revoked\n", id)
	return nil
}
