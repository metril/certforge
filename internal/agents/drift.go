package agents

import (
	"github.com/metril/certforge/internal/agentproto"
	"github.com/metril/certforge/internal/delivery"
)

// Deployment states.
const (
	statePending = "pending"
	stateOK      = "ok"
	stateFailed  = "failed"
	stateDrift   = "drift"
)

// ReportState is a deployment's state after one report result: failed when
// the agent says so, drift when what it installed differs from what was
// rendered, ok otherwise.
func ReportState(res agentproto.GrantResult, expected []agentproto.FileSpec) (state, errText string, missing, mismatched []string) {
	if res.State != agentproto.StateOK {
		e := res.Error
		if e == "" {
			e = "The agent reported a failure without a message."
		}
		return stateFailed, clip(e, 2048), nil, nil
	}
	missing, mismatched = delivery.Compare(expected, res.Installed)
	if len(missing)+len(mismatched) > 0 {
		return stateDrift, "", missing, mismatched
	}
	return stateOK, "", nil, nil
}

// HeartbeatState re-checks an ok or drifted deployment against a heartbeat;
// pending and failed deployments wait for a report.
func HeartbeatState(cur string, expected []agentproto.FileSpec, installed []agentproto.FileDigest) (next string, missing, mismatched []string) {
	if cur != stateOK && cur != stateDrift {
		return cur, nil, nil
	}
	missing, mismatched = delivery.Compare(expected, installed)
	if len(missing)+len(mismatched) > 0 {
		return stateDrift, missing, mismatched
	}
	return stateOK, nil, nil
}
