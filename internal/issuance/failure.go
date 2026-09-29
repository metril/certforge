package issuance

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/signer"
)

// FailureListener hears about every failed issuance attempt, after fail's
// own writes (FinishAttempt, then MarkFailed) have committed — the failure
// analogue of VersionListener. It is called for every failure regardless of
// notifications.failureThreshold; the listener (notify.Sources, Phase 6A
// Task 7) decides whether failures actually crosses it. OnFailure cannot
// fail the attempt: a panicking listener is recovered and logged, the same
// way notifyVersion protects OnVersion.
type FailureListener interface {
	OnFailure(ctx context.Context, cert Certificate, failures int, f FailureInfo)
}

// FailureInfo is a failed attempt's classified cause: never cause.Error()
// itself, which can carry a CA response URL, a resolver hostname or other
// detail unsafe to hand to an arbitrary notification channel (webhook,
// email, ...). Step is the timeline step that failed (lastFailedStep);
// ProblemType/Status come from a *signer.Error when the CA itself returned
// one (0/"" otherwise — a local pre-check like caa's own, or a rate-ledger
// failure, never reaches the CA); Class buckets the failure into one of
// acme, dns, caa, rate_limit, challenge, signer, internal (ClassifyFailure).
type FailureInfo struct {
	Step        string
	ProblemType string
	Status      int
	Class       string
}

// ClassifyFailure buckets a failed attempt's cause for cert.renewal_failed.
// step is the timeline step that failed (lastFailedStep's result, possibly
// "" for a pre-flight error before any step ran, for example "no CA
// configured"). Order matters: caa and rate_ledger are recognised by step
// name first — both fail from a local pre-check that never reaches the CA,
// so a *signer.Error's own Type (set only for a CA-returned rateLimited)
// is checked alongside the local rate-ledger's own LedgerExceeded; a
// *net.DNSError anywhere in cause's chain is "dns" (a challenge step's own
// propagation check, most commonly, or CAA's resolution before its
// forbidding-record case is reached); any other "challenge <name>" step is
// "challenge"; a *signer.Error whose Type the CA actually set is "acme";
// anything else that at least named a step (account, order, finalize, or a
// step name this function has never seen) is "signer"; a failure that
// named no step at all is "internal".
func ClassifyFailure(step string, cause error) FailureInfo {
	info := FailureInfo{Step: step, Class: "internal"}
	var se *signer.Error
	if errors.As(cause, &se) {
		info.ProblemType, info.Status = se.Type, se.Status
	}
	var le *LedgerExceeded
	var dnsErr *net.DNSError
	switch {
	case step == "caa":
		info.Class = "caa"
	case step == "rate_ledger", errors.As(cause, &le), info.ProblemType == rateLimitedType:
		info.Class = "rate_limit"
	case errors.As(cause, &dnsErr):
		info.Class = "dns"
	case strings.HasPrefix(step, "challenge"):
		info.Class = "challenge"
	case info.ProblemType != "":
		info.Class = "acme"
	case step != "":
		info.Class = "signer"
	}
	return info
}

// rateLimitedType is the ACME error type a CA-returned rate limit carries
// (also see rateLedgerStep, which reports the local ledger's own
// LedgerExceeded the same way for the attempt's own acme_error_type).
const rateLimitedType = "urn:ietf:params:acme:error:rateLimited"

// lastFailedStep returns the name of the most recently failed step in
// steps. tl.Step/tl.Finish always mark exactly the one step this attempt
// failed on as StepFailed (an earlier step either succeeded or was
// skipped, or the attempt would already have stopped there), so scanning
// from the end is defensive, not load-bearing. "" means no step ever ran
// (a pre-flight error, for example "no CA configured", before the first
// tl.Step call).
func lastFailedStep(steps []Step) string {
	for i := len(steps) - 1; i >= 0; i-- {
		if steps[i].Status == challenge.StepFailed {
			return steps[i].Name
		}
	}
	return ""
}
