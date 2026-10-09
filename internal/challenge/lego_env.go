package challenge

import (
	"fmt"
	"os"
	"sync"

	legochallenge "github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/providers/dns"
)

// lego providers read credentials from environment variables in their
// NewDNSProvider constructors. envMu serialises construction; each build sees
// only the credential's own values: every schema key (and its _FILE variant)
// is unset first, so the server's own environment never leaks in, and the
// previous environment is restored afterwards.
var (
	envMu     sync.Mutex
	newByName = dns.NewDNSChallengeProviderByName
)

// Build constructs the provider for code from a decrypted credential config.
func Build(code string, cfg map[string]string) (legochallenge.Provider, error) {
	e, ok := lookupEntry(code)
	if !ok {
		return nil, fmt.Errorf("unknown DNS provider %q", code)
	}
	// cfg is a stored credential: keys a schema update retired are dropped
	// (with a warning) rather than failing every issuance and renewal.
	cfg = dropRetired(e, cfg, true)
	for k, v := range cfg {
		// Belt and suspenders: SplitConfig already refuses to store a
		// serverPath value, but a credential created before that check
		// existed could still have one persisted, so Build refuses to use
		// it too.
		if e.serverPath[k] && v != "" {
			return nil, fmt.Errorf("%s: %w", k, ErrServerPath)
		}
		if v == Unchanged {
			return nil, fmt.Errorf("%s: %q is a write-only sentinel and cannot be built into a live provider", k, Unchanged)
		}
	}
	// buildCfg swaps a file-backed provider's inline credential for a path
	// into a private temp dir; cfg itself (with the inline value) is kept
	// for Scrub below, so a leaked credential value is still redacted.
	// Both transip and hyperone read the file eagerly during construction,
	// so dir is safe to remove as soon as construction returns, success or
	// not.
	buildCfg, dir, err := withFileBackedCreds(code, cfg)
	if err != nil {
		return nil, err
	}
	if dir != "" {
		defer os.RemoveAll(dir)
	}
	// scrubCfg covers both cfg's own inline values (a leaked credential) and
	// buildCfg's own values — chiefly the private temp file path
	// withFileBackedCreds substituted in place of an inline field (for
	// example HYPERONE_PASSPORT_LOCATION): hyperone's own open error quotes
	// that path verbatim, and cfg alone never contains it (the inline
	// field was deleted, not kept, when buildCfg was built), so scrubbing
	// only cfg left the server's own filesystem layout in the error.
	scrubCfg := scrubMap(cfg, buildCfg)

	if e.factory != nil {
		p, err := e.factory(buildCfg)
		if err != nil {
			return p, Scrub(err, code, scrubCfg)
		}
		return p, nil
	}
	buildCfg = forceAzureEnvAuth(e.meta.Code, buildCfg)
	envMu.Lock()
	defer envMu.Unlock()
	restore := isolateEnv(e.secret, buildCfg)
	defer restore()
	p, err := newByName(e.meta.Code)
	if err != nil {
		return nil, Scrub(fmt.Errorf("%s: %w", e.meta.Code, err), code, scrubCfg)
	}
	return p, nil
}

// scrubMap merges cfg and buildCfg into one map for Scrub: every value
// worth redacting from either, keyed by field name (the two never collide
// on a file-backed field — withFileBackedCreds deletes the inline key from
// buildCfg's copy before adding the path-env key, so cfg's version of that
// key is the only one preserved for that name; buildCfg's own path-env key
// has no counterpart in cfg at all). buildScrubList's minimum-length rule
// still applies to a merged non-secret value the same as any other.
func scrubMap(cfg, buildCfg map[string]string) map[string]string {
	m := make(map[string]string, len(cfg)+len(buildCfg))
	for k, v := range cfg {
		m[k] = v
	}
	for k, v := range buildCfg {
		if _, ok := m[k]; !ok {
			m[k] = v
		}
	}
	return m
}

func isolateEnv(schemaKeys map[string]bool, cfg map[string]string) (restore func()) {
	saved := map[string]*string{}
	for k := range schemaKeys {
		for _, name := range []string{k, k + "_FILE"} {
			if v, ok := os.LookupEnv(name); ok {
				saved[name] = &v
			} else {
				saved[name] = nil
			}
			os.Unsetenv(name)
		}
	}
	for k, v := range cfg {
		if v != "" {
			os.Setenv(k, v)
		}
	}
	return func() {
		for name, v := range saved {
			if v == nil {
				os.Unsetenv(name)
			} else {
				os.Setenv(name, *v)
			}
		}
	}
}
