package kek

import "context"

// Status is the server's key-encryption key and any rewrap in progress: the
// shape behind getKeysStatus's gen.KeysStatus, kept independent of
// internal/api/gen (see Info's doc comment).
type Status struct {
	Kind         string
	KEKID        string
	VaultAddress string
	Previous     []Ref
	CanaryOk     bool
	// Rewrap is the most recent rewrap, running or finished; nil if one has
	// never run.
	Rewrap *RewrapStatus
}

// Status reports the active KEK's identity, a canary round-trip and the
// most recent rewrap's progress (nil if none has ever run).
func (s *Service) Status(ctx context.Context) (Status, error) {
	canaryOk := s.Settings.VerifyCanary(ctx) == nil
	rw, err := s.loadStatus(ctx)
	if err != nil {
		return Status{}, err
	}
	return Status{
		Kind: s.Info.Kind, KEKID: s.Info.KEKID, VaultAddress: s.Info.VaultAddress,
		Previous: s.Info.Previous, CanaryOk: canaryOk, Rewrap: rw,
	}, nil
}
