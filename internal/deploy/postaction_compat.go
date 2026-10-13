package deploy

import (
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// Legacy post action validation, kept only until the API stops accepting a
// postAction on grants (the API task deletes this file with its handlers).

// Post action kinds.
const (
	PostActionSSH     = "ssh"
	PostActionPfSense = "pfsense"
)

// PostAction is the legacy single follow-up command of a server grant.
type PostAction struct {
	Kind           string    `json:"kind"`
	TargetID       uuid.UUID `json:"targetId"`
	Command        string    `json:"command"`
	TimeoutSeconds int       `json:"timeoutSeconds,omitempty"`
}

// TargetTypes are the deploy target types this kind runs against.
func (p *PostAction) TargetTypes() []string {
	if p.Kind == PostActionPfSense {
		return []string{TypePfSense}
	}
	return []string{TypeSSH, TypePiKVM}
}

// Validate checks the fields that do not need the database.
func (p *PostAction) Validate() error {
	p.Command = strings.TrimSpace(p.Command)
	if p.Kind == "" {
		p.Kind = PostActionSSH
	}
	switch {
	case p.Kind != PostActionSSH && p.Kind != PostActionPfSense:
		return errors.New("kind must be ssh or pfsense")
	case p.TargetID == uuid.Nil:
		return errors.New("targetId is required")
	case p.Command == "":
		return errors.New("command is required")
	case len(p.Command) > 512:
		return fmt.Errorf("command is longer than %d characters", 512)
	case p.TimeoutSeconds == 0:
		p.TimeoutSeconds = 60
	case p.TimeoutSeconds < 5 || p.TimeoutSeconds > 300:
		return errors.New("timeoutSeconds must be 5 to 300")
	}
	return nil
}
