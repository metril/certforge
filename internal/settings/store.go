// Package settings stores live configuration in the settings table: plain
// JSON values, envelope-encrypted secrets, and schema-validated UI sections.
package settings

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/jackc/pgx/v5"

	"github.com/metril/certforge/internal/crypto"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// ErrNotFound means the key (or its secret part) is not set.
var ErrNotFound = errors.New("settings: not found")

// Unchanged, sent as a secret field's value, keeps the stored secret.
const Unchanged = "__unchanged__"

// ErrUnchangedWithoutStored means Unchanged was sent for a secret that is not set.
var ErrUnchangedWithoutStored = errors.New("settings: __unchanged__ sent for a secret that is not set")

// SectionSecrets decrypts the section's stored secrets (an empty map when none).
func (s *Store) SectionSecrets(ctx context.Context, sec *Section) (map[string]string, error) {
	return s.sectionSecrets(ctx, s.q, sec)
}

// StoredSecretKeys lists the secret properties that hold a value, sorted.
func (s *Store) StoredSecretKeys(ctx context.Context, sec *Section) ([]string, error) {
	m, err := s.SectionSecrets(ctx, sec)
	if err != nil {
		return nil, err
	}
	return slices.Sorted(maps.Keys(m)), nil
}

func (s *Store) sectionSecrets(ctx context.Context, q *sqlcgen.Queries, sec *Section) (map[string]string, error) {
	out := map[string]string{}
	if len(sec.secrets) == 0 {
		return out, nil
	}
	row, err := q.GetSetting(ctx, sec.Key())
	if errors.Is(err, pgx.ErrNoRows) {
		return out, nil
	}
	if err != nil {
		return nil, fmt.Errorf("settings: get %s: %w", sec.Key(), err)
	}
	if row.Secret == nil {
		return out, nil
	}
	var b crypto.Blob
	if err := b.Unmarshal(row.Secret); err != nil {
		return nil, fmt.Errorf("settings: secret %s: %w", sec.Key(), err)
	}
	pt, err := s.env.Decrypt(ctx, b)
	if err != nil {
		return nil, fmt.Errorf("settings: secret %s: %w", sec.Key(), err)
	}
	if err := json.Unmarshal(pt, &out); err != nil {
		return nil, fmt.Errorf("settings: secret %s: %w", sec.Key(), err)
	}
	return out, nil
}

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

// GetSection returns the section's effective value (its own stored value, or
// the section's default when it was never saved) and the raw stored value
// (nil when it was never saved). The two differ for a caller that needs to
// tell "never explicitly configured" apart from "explicitly set to the
// built-in value" — the effective value alone always looks concrete once a
// default is filled in, which is exactly what made the issuance_defaults
// Global settings tab unable to tell the two apart (controller ruling,
// review fix round 1).
func (s *Store) GetSection(ctx context.Context, sec *Section) (value, stored json.RawMessage, err error) {
	var raw json.RawMessage
	err = s.Get(ctx, sec.Key(), &raw)
	if errors.Is(err, ErrNotFound) {
		return sec.Default, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return raw, raw, nil
}

// PutSection validates raw and stores it. Sections with secret properties
// must use PutSectionTx, which updates value and secret together.
func (s *Store) PutSection(ctx context.Context, sec *Section, raw json.RawMessage) error {
	if len(sec.secrets) > 0 {
		return fmt.Errorf("settings: section %s has secrets; use PutSectionTx", sec.Name)
	}
	if err := sec.Validate(raw); err != nil {
		return err
	}
	return s.Set(ctx, sec.Key(), raw)
}

// PutSectionTx validates raw and stores it inside tx. Secret properties go to
// the encrypted secret column: absent or Unchanged keeps the stored value,
// "" clears it, anything else replaces it.
func (s *Store) PutSectionTx(ctx context.Context, tx pgx.Tx, sec *Section, raw json.RawMessage) error {
	if err := sec.Validate(raw); err != nil {
		return err
	}
	pub, in, err := sec.split(raw)
	if err != nil {
		return err
	}
	q := s.q.WithTx(tx)
	b, err := json.Marshal(pub)
	if err != nil {
		return fmt.Errorf("settings: encode %s: %w", sec.Key(), err)
	}
	if err := q.UpsertSettingValue(ctx, sqlcgen.UpsertSettingValueParams{Key: sec.Key(), Value: b}); err != nil {
		return err
	}
	if len(in) == 0 {
		return nil
	}
	cur, err := s.sectionSecrets(ctx, q, sec)
	if err != nil {
		return err
	}
	changed := false
	for k, v := range in {
		switch v {
		case Unchanged:
			if _, ok := cur[k]; !ok {
				return fmt.Errorf("%w: %s", ErrUnchangedWithoutStored, k)
			}
		case "":
			if _, ok := cur[k]; ok {
				delete(cur, k)
				changed = true
			}
		default:
			if cur[k] != v {
				cur[k] = v
				changed = true
			}
		}
	}
	if !changed {
		return nil
	}
	pt, err := json.Marshal(cur)
	if err != nil {
		return err
	}
	blob, err := s.env.Encrypt(ctx, pt)
	if err != nil {
		return fmt.Errorf("settings: seal %s: %w", sec.Key(), err)
	}
	return q.UpsertSettingSecret(ctx, sqlcgen.UpsertSettingSecretParams{Key: sec.Key(), Secret: blob.Marshal()})
}
