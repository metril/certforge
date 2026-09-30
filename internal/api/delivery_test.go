package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/metril/certforge/internal/delivery"
	"github.com/metril/certforge/internal/targets"
)

// secretSchemaTarget is a minimal targets.Target for TestMapTargetErrRedacts:
// mapTargetErr only ever reads its Schema(), so nothing else is exercised.
type secretSchemaTarget struct{}

func (secretSchemaTarget) Type() string         { return "secret-schema-test" }
func (secretSchemaTarget) Name() string         { return "secret-schema-test" }
func (secretSchemaTarget) RunsOn() targets.Mode { return targets.Server }

func (secretSchemaTarget) KeyPolicy() targets.KeyPolicy { return targets.Never }

func (secretSchemaTarget) Schema() json.RawMessage {
	return json.RawMessage(`{"type":"object","properties":{"token":{"type":"string","secret":true,"description":"a secret"}}}`)
}

func (secretSchemaTarget) Parse(raw json.RawMessage) (targets.Config, error) {
	return targets.Config{Public: raw}, nil
}

func (secretSchemaTarget) Deploy(context.Context, targets.Request) (targets.Result, error) {
	return targets.Result{}, nil
}

// TestMapTargetErrRedactsSecret covers batch 2 review finding 3: a type's
// own Parse error can echo a rejected value straight back (a pattern check,
// or a type's own hand-written validation) — mapTargetErr must run it
// through targets.Redact with the raw request's own secret values before it
// ever reaches the problem body, for both a plain error and a
// delivery.FieldError.
func TestMapTargetErrRedactsSecret(t *testing.T) {
	raw := json.RawMessage(`{"token":"super-secret-value"}`)

	t.Run("plain error", func(t *testing.T) {
		err := fmt.Errorf("token %q is not a valid credential", "super-secret-value")
		got := mapTargetErr(err, secretSchemaTarget{}, raw)
		var he *HTTPError
		if !errors.As(got, &he) {
			t.Fatalf("mapTargetErr returned %T, want *HTTPError", got)
		}
		if strings.Contains(he.Detail, "super-secret-value") {
			t.Fatalf("problem detail leaked the secret: %q", he.Detail)
		}
		if !strings.Contains(he.Detail, "[redacted]") {
			t.Fatalf("problem detail not redacted: %q", he.Detail)
		}
	})

	t.Run("delivery.FieldError", func(t *testing.T) {
		fe := &delivery.FieldError{Field: "token", Msg: `rejected: "super-secret-value"`}
		got := mapTargetErr(fe, secretSchemaTarget{}, raw)
		var he *HTTPError
		if !errors.As(got, &he) {
			t.Fatalf("mapTargetErr returned %T, want *HTTPError", got)
		}
		if strings.Contains(he.Detail, "super-secret-value") {
			t.Fatalf("problem detail leaked the secret: %q", he.Detail)
		}
		if !strings.Contains(he.Detail, "[redacted]") {
			t.Fatalf("problem detail not redacted: %q", he.Detail)
		}
	})

	t.Run("Unchanged-without-stored sentinel is untouched", func(t *testing.T) {
		err := fmt.Errorf("token: %w", targets.ErrUnchangedWithoutStored)
		got := mapTargetErr(err, secretSchemaTarget{}, raw)
		var he *HTTPError
		if !errors.As(got, &he) || he.Detail != "token has no stored value" {
			t.Fatalf("mapTargetErr = %v, want \"token has no stored value\"", got)
		}
	})
}
