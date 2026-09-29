package httpx_test

import (
	"testing"

	"github.com/metril/certforge/internal/notify/httpx"
)

func TestURLPolicy(t *testing.T) {
	rejected := []string{
		"ftp://example.com/",
		"http://user:pass@example.com/",
		"http://127.0.0.1/",
		"http://[::1]/",
		"http://[::ffff:127.0.0.1]/",
		"http://0.0.0.0/",
		"http://[::]/",
		"http://169.254.169.254/",
		"http://[fe80::1]/",
		"http://localhost/",
	}
	for _, u := range rejected {
		if err := httpx.CheckURL(u, false); err == nil {
			t.Errorf("CheckURL(%q, false) = nil, want error", u)
		}
	}

	allowed := []string{
		"http://10.0.0.5/",
		"https://192.168.1.10/",
	}
	for _, u := range allowed {
		if err := httpx.CheckURL(u, false); err != nil {
			t.Errorf("CheckURL(%q, false) = %v, want nil", u, err)
		}
	}

	// allowLoopback admits loopback and link-local, but the metadata
	// addresses stay blocked regardless.
	admittedUnderAllowLoopback := []string{
		"http://127.0.0.1/",
		"http://[::1]/",
		"http://[fe80::1]/",
		"http://localhost/",
	}
	for _, u := range admittedUnderAllowLoopback {
		if err := httpx.CheckURL(u, true); err != nil {
			t.Errorf("CheckURL(%q, true) = %v, want nil", u, err)
		}
	}

	stillBlockedUnderAllowLoopback := []string{
		"http://169.254.169.254/",
		"http://[::ffff:169.254.169.254]/",
		"http://[fd00:ec2::254]/",
	}
	for _, u := range stillBlockedUnderAllowLoopback {
		if err := httpx.CheckURL(u, true); err == nil {
			t.Errorf("CheckURL(%q, true) = nil, want error", u)
		}
	}
}

func TestCheckHost(t *testing.T) {
	if err := httpx.CheckHost("example.com", false); err != nil {
		t.Errorf("CheckHost(hostname, false) = %v, want nil", err)
	}
	if err := httpx.CheckHost("127.0.0.1", false); err == nil {
		t.Error("CheckHost(loopback, false) = nil, want error")
	}
	if err := httpx.CheckHost("127.0.0.1", true); err != nil {
		t.Errorf("CheckHost(loopback, true) = %v, want nil", err)
	}
}
