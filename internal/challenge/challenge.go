// Package challenge proves control of certificate names for ACME. It routes
// lego's DNS-01 Present/CleanUp per name to the matching verification rule
// (a lego DNS provider built from a stored credential, or manual-dns), and
// publishes the JSON Schemas of every DNS provider.
package challenge

import (
	"context"
	"time"

	legochallenge "github.com/go-acme/lego/v4/challenge"
	"github.com/go-acme/lego/v4/challenge/dns01"
)

// Type is a challenge type.
type Type string

const (
	DNS01     Type = "dns-01"
	ManualDNS Type = "manual-dns"
	HTTP01    Type = "http-01"
	TLSALPN01 Type = "tls-alpn-01"
)

// ChallengeProvider is CertForge's challenge interface (spec "Interfaces").
type ChallengeProvider interface {
	Type() Type
	Present(ctx context.Context, domain, token, keyAuth string) error
	CleanUp(ctx context.Context, domain, token, keyAuth string) error
	Timeout() (timeout, interval time.Duration)
}

// Waiter is implemented by providers that need a human before propagation
// checks start (manual-dns).
type Waiter interface {
	WaitReady(ctx context.Context) error
	WaitBudget() time.Duration
}

// Step statuses written to the attempt timeline.
const (
	StepRunning       = "running"
	StepSuccess       = "success"
	StepFailed        = "failed"
	StepSkipped       = "skipped"
	StepWaitingManual = "waiting_manual"
)

// StepSink receives timeline updates; issuance.Timeline implements it.
type StepSink interface {
	Step(name, status, message string)
}

// NopSink discards steps.
type NopSink struct{}

// Step implements StepSink by discarding the update.
func (NopSink) Step(string, string, string) {}

type legoProvider struct {
	code string
	p    legochallenge.Provider
	cfg  map[string]string
}

// WrapLego adapts a lego DNS provider to ChallengeProvider. cfg is the
// credential's decrypted config (secrets included): a live Present/CleanUp
// failure is scrubbed against it (Scrub) before it reaches the worker's
// attempt log or last_error, since lego providers commonly echo the failed
// request (including credential values) in their error text.
func WrapLego(code string, p legochallenge.Provider, cfg map[string]string) ChallengeProvider {
	return legoProvider{code: code, p: p, cfg: cfg}
}

func (l legoProvider) Type() Type { return DNS01 }

func (l legoProvider) Present(_ context.Context, domain, token, keyAuth string) error {
	return Scrub(l.p.Present(domain, token, keyAuth), l.code, l.cfg)
}

func (l legoProvider) CleanUp(_ context.Context, domain, token, keyAuth string) error {
	return Scrub(l.p.CleanUp(domain, token, keyAuth), l.code, l.cfg)
}

func (l legoProvider) Timeout() (time.Duration, time.Duration) {
	if pt, ok := l.p.(legochallenge.ProviderTimeout); ok {
		return pt.Timeout()
	}
	return dns01.DefaultPropagationTimeout, dns01.DefaultPollingInterval
}
