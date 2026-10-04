package audit

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/metrics"
)

// SumForTest exposes the chain hash so external tests can build legacy rows.
func (a *Auditor) SumForTest(alg string, prev []byte, ts time.Time, actorType, actorID, action, resourceType, resourceID string,
	orgID *uuid.UUID, ip string, details []byte) []byte {
	return a.sum(alg, prev, ts, actorType, actorID, action, resourceType, resourceID, orgID, ip, details)
}

// WriteAnchorForTest stores a correctly MACed head anchor for (id, hash).
func (a *Auditor) WriteAnchorForTest(ctx context.Context, id int64, hash []byte) error {
	return a.writeAnchor(ctx, sqlcgen.New(a.pool), id, hash)
}

// ResetHeadForTest returns the head gauge to a fresh process's state.
func ResetHeadForTest() {
	headMu.Lock()
	defer headMu.Unlock()
	headMax = 0
	metrics.AuditHeadID.Set(0)
}
