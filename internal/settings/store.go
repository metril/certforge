// Package settings stores live configuration in the settings table: plain
// JSON values, envelope-encrypted secrets, and schema-validated UI sections.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// ErrNotFound means the key (or its secret part) is not set.
var ErrNotFound = errors.New("settings: not found")

// Store reads and writes the settings table.
type Store struct {
	q   *sqlcgen.Queries
	env *crypto.Envelope
}

// NewStore returns a Store that seals secrets with env.
func NewStore(q *sqlcgen.Queries, env *crypto.Envelope) *Store {
	return &Store{q: q, env: env}
}

// Get decodes the JSON value at key into out.
func (s *Store) Get(ctx context.Context, key string, out any) error {
	row, err := s.q.GetSetting(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("settings: get %s: %w", key, err)
	}
	if err := json.Unmarshal(row.Value, out); err != nil {
		return fmt.Errorf("settings: decode %s: %w", key, err)
	}
	return nil
}

// GetTx is Get scoped to an existing transaction, for callers (issuance's
// delete-protection checks) that need this read to be part of a larger
// transaction instead of a separate pool-bound query.
func (s *Store) GetTx(ctx context.Context, tx pgx.Tx, key string, out any) error {
	row, err := s.q.WithTx(tx).GetSetting(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return fmt.Errorf("settings: get %s: %w", key, err)
	}
	if err := json.Unmarshal(row.Value, out); err != nil {
		return fmt.Errorf("settings: decode %s: %w", key, err)
	}
	return nil
}

// Set stores v as JSON at key.
func (s *Store) Set(ctx context.Context, key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("settings: encode %s: %w", key, err)
	}
	return s.q.UpsertSettingValue(ctx, sqlcgen.UpsertSettingValueParams{Key: key, Value: b})
}

// GetSecret decrypts the secret at key.
func (s *Store) GetSecret(ctx context.Context, key string) ([]byte, error) {
	row, err := s.q.GetSetting(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("settings: get %s: %w", key, err)
	}
	if row.Secret == nil {
		return nil, ErrNotFound
	}
	var b crypto.Blob
	if err := b.Unmarshal(row.Secret); err != nil {
		return nil, fmt.Errorf("settings: secret %s: %w", key, err)
	}
	pt, err := s.env.Decrypt(ctx, b)
	if err != nil {
		return nil, fmt.Errorf("settings: secret %s: %w", key, err)
	}
	return pt, nil
}

// SetSecret encrypts plaintext and stores it at key.
func (s *Store) SetSecret(ctx context.Context, key string, plaintext []byte) error {
	b, err := s.env.Encrypt(ctx, plaintext)
	if err != nil {
		return fmt.Errorf("settings: seal %s: %w", key, err)
	}
	return s.q.UpsertSettingSecret(ctx, sqlcgen.UpsertSettingSecretParams{Key: key, Secret: b.Marshal()})
}

// GetSection returns the stored section value, or its default when unset.
func (s *Store) GetSection(ctx context.Context, sec *Section) (json.RawMessage, error) {
	var raw json.RawMessage
	err := s.Get(ctx, sec.Key(), &raw)
	if errors.Is(err, ErrNotFound) {
		return sec.Default, nil
	}
	return raw, err
}

// PutSection validates raw against the section schema and stores it.
func (s *Store) PutSection(ctx context.Context, sec *Section, raw json.RawMessage) error {
	if err := sec.Validate(raw); err != nil {
		return err
	}
	return s.Set(ctx, sec.Key(), raw)
}

// PutSectionTx is PutSection scoped to an existing transaction, for callers
// that must validate and store a section alongside other locked reads in
// the same transaction (for example issuance_defaults's referenced-CA/
// account key-share locks).
func (s *Store) PutSectionTx(ctx context.Context, tx pgx.Tx, sec *Section, raw json.RawMessage) error {
	if err := sec.Validate(raw); err != nil {
		return err
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return fmt.Errorf("settings: encode %s: %w", sec.Key(), err)
	}
	return s.q.WithTx(tx).UpsertSettingValue(ctx, sqlcgen.UpsertSettingValueParams{Key: sec.Key(), Value: b})
}
