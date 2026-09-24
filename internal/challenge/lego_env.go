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
	for k := range cfg {
		if _, known := e.secret[k]; !known {
			return nil, fmt.Errorf("%w %q for provider %s", ErrUnknownField, k, e.meta.Code)
		}
	}
	if e.factory != nil {
		return e.factory(cfg)
	}
	envMu.Lock()
	defer envMu.Unlock()
	restore := isolateEnv(e.secret, cfg)
	defer restore()
	p, err := newByName(e.meta.Code)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", e.meta.Code, err)
	}
	return p, nil
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
