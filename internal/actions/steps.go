package actions

import (
	"encoding/json"
	"fmt"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/targets"
)

// MaxSteps caps both the raw steps of a grant and the actions they expand to.
const MaxSteps = 32

// Step is one entry of a grant's step list: an action or a group of actions.
type Step struct {
	Action *uuid.UUID `json:"action,omitempty"`
	Group  *uuid.UUID `json:"group,omitempty"`
}

// ActionRef is one expanded action, as the lookup describes it.
type ActionRef struct {
	ID             uuid.UUID
	Kind           string
	Phase          string
	RunsOn         targets.Mode
	Optional       bool
	TimeoutSeconds int
	Config         json.RawMessage
}

// ParseSteps decodes and validates a grant's steps: at most 32, each with
// exactly one of action or group. Empty or null input yields no steps.
func ParseSteps(raw json.RawMessage) ([]Step, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var steps []Step
	if err := json.Unmarshal(raw, &steps); err != nil {
		return nil, &delivery.FieldError{Field: "steps", Msg: "must be a list of {action} or {group} objects"}
	}
	if len(steps) > MaxSteps {
		return nil, &delivery.FieldError{Field: "steps", Msg: fmt.Sprintf("at most %d steps", MaxSteps)}
	}
	for i, s := range steps {
		if (s.Action == nil) == (s.Group == nil) {
			return nil, &delivery.FieldError{Field: fmt.Sprintf("steps[%d]", i), Msg: "set exactly one of action or group"}
		}
	}
	return steps, nil
}

// Expand resolves steps into the ordered actions to run: a group expands, in
// order, to its member actions via groups. Unknown ids and more than 32
// expanded actions are errors naming the step.
func Expand(steps []Step, groups map[uuid.UUID][]uuid.UUID, lookup func(uuid.UUID) (ActionRef, bool)) ([]ActionRef, error) {
	var out []ActionRef
	for i, s := range steps {
		field := fmt.Sprintf("steps[%d]", i)
		var ids []uuid.UUID
		switch {
		case s.Action != nil && s.Group == nil:
			ids = []uuid.UUID{*s.Action}
		case s.Group != nil && s.Action == nil:
			g, ok := groups[*s.Group]
			if !ok {
				return nil, &delivery.FieldError{Field: field, Msg: "unknown action group"}
			}
			ids = g
		default:
			return nil, &delivery.FieldError{Field: field, Msg: "set exactly one of action or group"}
		}
		for _, id := range ids {
			ref, ok := lookup(id)
			if !ok {
				return nil, &delivery.FieldError{Field: field, Msg: "unknown action"}
			}
			out = append(out, ref)
			if len(out) > MaxSteps {
				return nil, &delivery.FieldError{Field: field, Msg: fmt.Sprintf("steps expand to more than %d actions", MaxSteps)}
			}
		}
	}
	return out, nil
}

// RunsOnMismatch returns the index of the first ref that cannot run on mode
// (Agent or Server), or -1 when all can.
func RunsOnMismatch(refs []ActionRef, mode targets.Mode) int {
	for i, r := range refs {
		if r.RunsOn != targets.Either && r.RunsOn != mode {
			return i
		}
	}
	return -1
}

// DirectActionIDs returns the action ids named directly by raw steps (groups
// are not expanded); malformed input yields none.
func DirectActionIDs(raw []byte) []uuid.UUID {
	var steps []Step
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

// StepsOfActions builds a step list naming each action id in order.
func StepsOfActions(ids []uuid.UUID) []Step {
	steps := make([]Step, 0, len(ids))
	for i := range ids {
		steps = append(steps, Step{Action: &ids[i]})
	}
	return steps
}
