package api

import (
	"context"
	"errors"

	"github.com/metril/certforge/internal/api/gen"
	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/kek"
)

// GetKeysStatus reports the active KEK's identity, previous KEKs still
// configured, a canary round-trip and the most recent rewrap's progress.
func (s *Server) GetKeysStatus(ctx context.Context, _ gen.GetKeysStatusRequestObject) (gen.GetKeysStatusResponseObject, error) {
	p, err := authorize(ctx, authz.ActionSettingsRead, nil)
	if err != nil {
		return nil, err
	}
	st, err := s.d.Keys.Status(ctx)
	if err != nil {
		return nil, err
	}
	// The Vault address is infrastructure detail: only a principal who can
	// change settings (global settings:write) sees it.
	if !authz.Can(p, authz.ActionSettingsWrite, nil) {
		st.VaultAddress = ""
	}
	return gen.GetKeysStatus200JSONResponse(keysStatusToGen(st)), nil
}

// StartRewrap enqueues a rewrap job, 409 if one is already running.
func (s *Server) StartRewrap(ctx context.Context, _ gen.StartRewrapRequestObject) (gen.StartRewrapResponseObject, error) {
	if _, err := authorize(ctx, authz.ActionSettingsWrite, nil); err != nil {
		return nil, err
	}
	if err := s.d.Keys.StartRewrap(ctx); err != nil {
		if errors.Is(err, kek.ErrRunning) {
			return nil, conflict("a rewrap is already running")
		}
		return nil, err
	}
	s.audit(ctx, audit.Event{Action: "kek.rewrap_started", ResourceType: "kek",
		Details: map[string]any{"activeKekId": s.d.Keys.Info.KEKID}})
	st, err := s.d.Keys.Status(ctx)
	if err != nil {
		return nil, err
	}
	return gen.StartRewrap202JSONResponse(keysStatusToGen(st)), nil
}

// keysStatusToGen converts kek.Status to the wire shape: kek is kept
// independent of internal/api/gen (crypto.TransitAPI's doc comment explains
// the same pattern for internal/crypto), so the mapping happens here.
func keysStatusToGen(st kek.Status) gen.KeysStatus {
	previous := make([]gen.KekRef, len(st.Previous))
	for i, r := range st.Previous {
		previous[i] = gen.KekRef{Kind: gen.KekKind(r.Kind), KekId: r.KEKID}
	}
	out := gen.KeysStatus{
		Kind: gen.KekKind(st.Kind), KekId: st.KEKID, CanaryOk: st.CanaryOk, Previous: previous,
	}
	if st.VaultAddress != "" {
		out.VaultAddress = &st.VaultAddress
	}
	if st.Rewrap != nil {
		rw := rewrapStatusToGen(*st.Rewrap)
		out.Rewrap = &rw
	}
	return out
}

func rewrapStatusToGen(rw kek.RewrapStatus) gen.RewrapStatus {
	tables := make([]gen.RewrapTableStatus, len(rw.Tables))
	for i, t := range rw.Tables {
		tables[i] = gen.RewrapTableStatus{
			Table: gen.RewrapTable(t.Table), Scanned: t.Scanned, Rewrapped: t.Rewrapped, Remaining: t.Remaining,
		}
	}
	out := gen.RewrapStatus{
		Running: rw.Running, StartedAt: rw.StartedAt, FinishedAt: rw.FinishedAt,
		ActiveKekId: rw.ActiveKEKID, PreviousKekIds: rw.PreviousKEKIDs, Tables: tables, Remaining: rw.Remaining,
	}
	if rw.Error != "" {
		out.Error = &rw.Error
	}
	return out
}
