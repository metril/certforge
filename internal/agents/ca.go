package agents

import (
	"context"
	"errors"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/agentca"
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/audit"
)

// ReloadListener re-issues the listener certificate after a settings change.
func (s *Service) ReloadListener(ctx context.Context) error {
	if s.Listener == nil {
		return nil
	}
	return s.Listener.Reload(ctx)
}

// pushTrust reloads the listener and sends the trust bundle to every
// connected agent (agents write it to ca.pem, renew at once and reconnect,
// so a rotation moves connected agents to the new CA immediately).
func (s *Service) pushTrust(ctx context.Context) {
	if err := s.ReloadListener(ctx); err != nil {
		s.log().Error("agent listener not reloaded after a CA change", "err", err)
	}
	trusted, err := s.CA.Trusted(ctx)
	if err != nil {
		s.log().Error("agent trust bundle not read", "err", err)
		return
	}
	if s.Hub != nil {
		s.Hub.Broadcast(agentproto.TrustBundleUpdate{Bundle: string(agentca.BundlePEM(trusted))})
	}
}

// RotateCA creates a new active agent CA that signs new agent certificates;
// the previous one stays trusted (retiring) and keeps signing the listener
// certificate until it is retired. A reload failure only logs (the listener
// still serves the unchanged, still-trusted previous CA), so the broadcast
// still goes: it is harmless since the listener certificate is unchanged.
func (s *Service) RotateCA(ctx context.Context) (*agentca.CA, error) {
	ca, prev, err := s.CA.Rotate(ctx)
	if err != nil {
		return nil, err
	}
	s.pushTrust(ctx)
	s.audit(ctx, audit.Event{Action: "agent_ca.rotate", ResourceType: "agent_ca", ResourceID: ca.ID.String(),
		Details: map[string]any{"fingerprint": agentca.Fingerprint(ca.Cert.Raw), "previousId": prev}})
	return ca, nil
}

// RetireCA stops trusting a retiring CA no live agent certificate depends on.
// Unlike RotateCA, a reload failure here is not swallowed: the listener must
// be re-signed by the new oldest CA before agents that only trust the CAs in
// their current bundle stop reaching it, so the caller sees the failure
// (500) and no trust bundle is broadcast against a listener that isn't
// actually reachable under it yet. The retire itself already committed, so
// the audit event is still recorded, with reloadFailed noting the gap.
func (s *Service) RetireCA(ctx context.Context, id uuid.UUID) error {
	err := s.CA.Retire(ctx, id)
	var inUse *agentca.InUseError
	switch {
	case errors.Is(err, agentca.ErrNotFound):
		return notFound("agent CA %s", id)
	case errors.Is(err, agentca.ErrActive):
		return conflict("The active agent CA cannot be retired; rotate first.")
	case errors.As(err, &inUse):
		return conflict("%d active agent certificates were issued by this CA; connected agents renew when they get the new trust bundle, pull-mode and offline agents when their certificate comes due. Wait for them or re-enrol them.", inUse.N)
	case err != nil:
		return err
	}
	if reloadErr := s.ReloadListener(ctx); reloadErr != nil {
		s.audit(ctx, audit.Event{Action: "agent_ca.retire", ResourceType: "agent_ca", ResourceID: id.String(),
			Details: map[string]any{"reloadFailed": true}})
		return reloadErr
	}
	if trusted, err := s.CA.Trusted(ctx); err != nil {
		s.log().Error("agent trust bundle not read", "err", err)
	} else if s.Hub != nil {
		s.Hub.Broadcast(agentproto.TrustBundleUpdate{Bundle: string(agentca.BundlePEM(trusted))})
	}
	s.audit(ctx, audit.Event{Action: "agent_ca.retire", ResourceType: "agent_ca", ResourceID: id.String()})
	return nil
}
