package agents

import (
	"encoding/json"

	"github.com/google/uuid"
)

// StepActionIDs returns the action ids named directly by a grant's steps
// (groups are not expanded yet).
func StepActionIDs(raw []byte) []uuid.UUID {
	var steps []struct {
		Action *uuid.UUID `json:"action"`
	}
	if json.Unmarshal(raw, &steps) != nil {
		return nil
	}
	var ids []uuid.UUID
	for _, s := range steps {
		if s.Action != nil {
			ids = append(ids, *s.Action)
		}
	}
	return ids
}

// stepsOfActions builds a steps value naming each action id in order.
func stepsOfActions(ids []uuid.UUID) []byte {
	steps := make([]map[string]uuid.UUID, 0, len(ids))
	for _, id := range ids {
		steps = append(steps, map[string]uuid.UUID{"action": id})
	}
	b, _ := json.Marshal(steps)
	return b
}
