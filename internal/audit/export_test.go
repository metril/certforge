package audit

import (
	"time"

	"github.com/google/uuid"
)

// SumForTest exposes the chain hash so external tests can build legacy rows.
func (a *Auditor) SumForTest(alg string, prev []byte, ts time.Time, actorType, actorID, action, resourceType, resourceID string,
	orgID *uuid.UUID, ip string, details []byte) []byte {
	return a.sum(alg, prev, ts, actorType, actorID, action, resourceType, resourceID, orgID, ip, details)
}
