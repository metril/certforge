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
	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db"
	"github.com/metril/certforge/internal/db/sqlcgen"
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
	cfg, _, pool, err := openDeps(ctx)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := db.Migrate(ctx, pool); err != nil {
		return err
	}
	env := crypto.NewEnvelope(crypto.NewStaticWrapper(crypto.KeyID(cfg.KEK.Key), cfg.KEK.Key))
	store := settings.NewStore(sqlcgen.New(pool), env)
	// Run the KEK canary before constructing the auditor: with the wrong
	// KEK, events written here would be keyed wrong and never verify under
	// the right one (controller ruling C6).
	if err := store.EnsureCanary(ctx); err != nil {
		return fmt.Errorf("KEK canary check failed; refusing to write audit events under the wrong KEK: %w", err)
	}
	aud := audit.New(pool, crypto.DeriveKey(cfg.KEK.Key, "certforge-audit"))
	id, err := setup.New(pool, aud, settings.DefaultRegistry()).SetAdminPassword(ctx, password)
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "local admin %s: password set, existing sessions revoked\n", id)
	return nil
}
