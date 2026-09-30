package targets_test

import (
	"testing"

	"github.com/metril/certforge/internal/notify/httpx"
	"github.com/metril/certforge/internal/targets"
)

func TestFactoryForcesLoopbackFlag(t *testing.T) {
	for _, allow := range []bool{true, false} {
		f := targets.HTTPFactory{AllowLoopback: allow}
		// The caller's own opts.AllowLoopback (the opposite of f's) must be
		// overridden by f's own value, not merely defaulted.
		c, err := f.New(httpx.Options{AllowLoopback: !allow})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		if c == nil {
			t.Fatal("New returned a nil client")
		}
		wantErr := httpx.CheckHost("127.0.0.1", allow)
		gotErr := httpx.CheckURL("http://127.0.0.1/", allow)
		if (wantErr == nil) != (gotErr == nil) {
			t.Fatalf("allow=%v: CheckHost err=%v, CheckURL err=%v mismatch", allow, wantErr, gotErr)
		}
	}
}
