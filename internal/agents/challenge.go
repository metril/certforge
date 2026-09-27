package agents

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// DefaultChallengeReadyTimeout is Service.ChallengeReadyTimeout's value
// when unset.
const DefaultChallengeReadyTimeout = 30 * time.Second

// waitKey identifies one outstanding challenge_present waiting on its
// agent's challenge_ready reply.
type waitKey struct {
	client uuid.UUID
	token  string
}

// challengeWaiters hands each Present call a channel for the matching
// challenge_ready reply, keyed by (clientID, token); ChallengeReady (the
// socket handler) looks the channel up by the same key and delivers the
// reply on it. Zero value is ready to use.
type challengeWaiters struct {
	mu sync.Mutex
	m  map[waitKey]chan agentproto.ChallengeReady
}

// register returns a fresh, buffered channel for (clientID, token),
// replacing whatever was registered before it (a rule reused across a
// retried attempt uses a fresh token each time, so a collision here would
// only ever be a stale entry a canceled Present never got to forget).
func (w *challengeWaiters) register(clientID uuid.UUID, token string) chan agentproto.ChallengeReady {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.m == nil {
		w.m = map[waitKey]chan agentproto.ChallengeReady{}
	}
	ch := make(chan agentproto.ChallengeReady, 1)
	w.m[waitKey{clientID, token}] = ch
	return ch
}

// forget removes the waiter for (clientID, token); called once Present's
// wait ends, however it ends, so a late duplicate reply finds no waiter.
func (w *challengeWaiters) forget(clientID uuid.UUID, token string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.m, waitKey{clientID, token})
}

// deliver hands m to the waiter registered for (clientID, m.Token), if
// any; a reply with no matching waiter (already timed out, or unsolicited)
// is silently dropped.
func (w *challengeWaiters) deliver(clientID uuid.UUID, m agentproto.ChallengeReady) {
	w.mu.Lock()
	defer w.mu.Unlock()
	ch, ok := w.m[waitKey{clientID, m.Token}]
	if !ok {
		return
	}
	select {
	case ch <- m:
	default:
	}
}

func (s *Service) challengeReadyTimeout() time.Duration {
	if s.ChallengeReadyTimeout > 0 {
		return s.ChallengeReadyTimeout
	}
	return DefaultChallengeReadyTimeout
}

// Provider implements challenge.AgentRelay: it returns the ChallengeProvider
// that relays Present/CleanUp for method to clientID's agent over its
// WebSocket. Rule validation (issuance.Store's lockRuleClientsInIDOrder and
// checkRuleClientCapability) already checked, when the rule was written,
// that clientID names an active, same-org client with the method's
// capability (or, for http-01, its own webroot); a client no longer found
// here (deleted since, or never existed) is reported the same way as one
// whose agent is offline, since neither can serve the challenge.
func (s *Service) Provider(ctx context.Context, orgID, clientID uuid.UUID, m challenge.Method, webroot string) (challenge.ChallengeProvider, error) {
	c, err := s.Q.GetClient(ctx, sqlcgen.GetClientParams{ID: clientID, OrgID: orgID})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("client %s is offline or cannot serve challenges", clientID)
	}
	if err != nil {
		return nil, err
	}
	return &agentChallengeProvider{svc: s, clientID: clientID, name: c.Name, active: c.Status == "active",
		method: m, webroot: webroot}, nil
}

// ChallengeReady handles the agent's reply to challenge_present (dispatched
// by OnMessage), waking the Present call waiting on (clientID, token).
func (s *Service) ChallengeReady(_ context.Context, clientID uuid.UUID, v agentproto.ChallengeReady) error {
	s.waiters.deliver(clientID, v)
	return nil
}

// agentChallengeProvider implements challenge.ChallengeProvider by asking
// clientID's agent, over its WebSocket, to present or clean up an http-01
// or tls-alpn-01 challenge.
type agentChallengeProvider struct {
	svc      *Service
	clientID uuid.UUID
	name     string
	active   bool
	method   challenge.Method
	webroot  string
}

func (p *agentChallengeProvider) Type() challenge.Type { return p.method.Type() }

// connectedPollInterval bounds how long a dropped socket can go unnoticed
// while Present is waiting: without a poll, Present would only find out
// once the full ChallengeReadyTimeout elapsed (fix round 1, Minor finding).
const connectedPollInterval = 200 * time.Millisecond

// Present sends challenge_present and waits for challenge_ready, up to
// svc.ChallengeReadyTimeout (DefaultChallengeReadyTimeout unless a test
// shortens it), polling Hub.Connected every connectedPollInterval so a
// socket that drops mid-wait is noticed promptly instead of only once the
// timeout elapses. lego's http01.Challenge.Solve (and tls-alpn-01's) calls
// CleanUp only once Present has returned successfully, so once
// challenge_present has actually reached the agent (Hub.Send below
// succeeded), every other return path — a timeout, an error reply, a
// dropped socket, or the context ending — best-effort sends
// challenge_cleanup itself; otherwise a late or unlucky agent would keep
// serving a token nothing is ever going to clean up (fix round 1, Important
// finding).
func (p *agentChallengeProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	if !p.active || p.svc.Hub == nil || !p.svc.Hub.Connected(p.clientID) {
		return fmt.Errorf("client %s is offline or cannot serve challenges", p.name)
	}
	ch := p.svc.waiters.register(p.clientID, token)
	defer p.svc.waiters.forget(p.clientID, token)
	msg := agentproto.ChallengePresent{Token: token, KeyAuth: keyAuth, Domain: domain, Method: string(p.method), Webroot: p.webroot}
	if !p.svc.Hub.Send(p.clientID, msg) {
		return fmt.Errorf("client %s is offline or cannot serve challenges", p.name)
	}
	timeout := p.svc.challengeReadyTimeout()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	poll := time.NewTicker(connectedPollInterval)
	defer poll.Stop()
	for {
		select {
		case reply := <-ch:
			if reply.Error != "" {
				p.cleanup(token)
				return fmt.Errorf("client %s: %s", p.name, reply.Error)
			}
			return nil
		case <-timer.C:
			p.cleanup(token)
			return fmt.Errorf("client %s did not confirm the challenge within %s", p.name, timeout)
		case <-poll.C:
			if !p.svc.Hub.Connected(p.clientID) {
				p.cleanup(token)
				return fmt.Errorf("client %s is offline or cannot serve challenges", p.name)
			}
		case <-ctx.Done():
			p.cleanup(token)
			return ctx.Err()
		}
	}
}

// cleanup sends challenge_cleanup for token; best-effort (no reply is
// waited for), same as CleanUp.
func (p *agentChallengeProvider) cleanup(token string) {
	if p.svc.Hub != nil {
		p.svc.Hub.Send(p.clientID, agentproto.ChallengeCleanup{Token: token})
	}
}

// CleanUp asks the agent to stop serving token; best-effort, since the
// order is already finishing (successfully or not) by the time this runs.
func (p *agentChallengeProvider) CleanUp(_ context.Context, _, token, _ string) error {
	p.cleanup(token)
	return nil
}

// Timeout implements challenge.ChallengeProvider; unused for http-01 or
// tls-alpn-01 (the CA fetches the resource directly, no propagation
// polling), same as serverHTTP01's.
func (p *agentChallengeProvider) Timeout() (time.Duration, time.Duration) {
	return 60 * time.Second, 2 * time.Second
}
