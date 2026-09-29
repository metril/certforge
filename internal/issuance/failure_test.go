package issuance

import (
	"errors"
	"net"
	"testing"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/signer"
)

func TestClassifyFailureCAA(t *testing.T) {
	f := ClassifyFailure("caa", errors.New("forbidden by CAA"))
	if f.Class != "caa" || f.Step != "caa" {
		t.Fatalf("f = %+v", f)
	}
}

func TestClassifyFailureRateLedger(t *testing.T) {
	f := ClassifyFailure("rate_ledger", &LedgerExceeded{})
	if f.Class != "rate_limit" {
		t.Fatalf("f = %+v", f)
	}
}

func TestClassifyFailureCARateLimited(t *testing.T) {
	cause := &signer.Error{Type: "urn:ietf:params:acme:error:rateLimited", Status: 429}
	f := ClassifyFailure("order", cause)
	if f.Class != "rate_limit" || f.ProblemType != cause.Type || f.Status != 429 {
		t.Fatalf("f = %+v", f)
	}
}

func TestClassifyFailureDNS(t *testing.T) {
	cause := &net.DNSError{Err: "no such host", Name: "dns.internal", IsNotFound: true}
	f := ClassifyFailure("challenge example.test", cause)
	if f.Class != "dns" {
		t.Fatalf("f = %+v", f)
	}
}

func TestClassifyFailureChallenge(t *testing.T) {
	f := ClassifyFailure("challenge example.test", errors.New("timed out waiting for validation"))
	if f.Class != "challenge" {
		t.Fatalf("f = %+v", f)
	}
}

func TestClassifyFailureACME(t *testing.T) {
	cause := &signer.Error{Type: "urn:ietf:params:acme:error:unauthorized", Status: 403}
	f := ClassifyFailure("order", cause)
	if f.Class != "acme" || f.ProblemType != cause.Type || f.Status != 403 {
		t.Fatalf("f = %+v", f)
	}
}

func TestClassifyFailureSigner(t *testing.T) {
	f := ClassifyFailure("account", errors.New("db unavailable"))
	if f.Class != "signer" {
		t.Fatalf("f = %+v", f)
	}
}

func TestClassifyFailureInternal(t *testing.T) {
	f := ClassifyFailure("", errors.New("no CA configured"))
	if f.Class != "internal" {
		t.Fatalf("f = %+v", f)
	}
}

func TestLastFailedStep(t *testing.T) {
	steps := []Step{
		{Name: "account", Status: challenge.StepSuccess},
		{Name: "order", Status: challenge.StepFailed},
	}
	if got := lastFailedStep(steps); got != "order" {
		t.Fatalf("lastFailedStep = %q, want %q", got, "order")
	}
}

func TestLastFailedStepNoneFailed(t *testing.T) {
	steps := []Step{{Name: "account", Status: challenge.StepSuccess}}
	if got := lastFailedStep(steps); got != "" {
		t.Fatalf("lastFailedStep = %q, want empty", got)
	}
}
