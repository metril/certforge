package issuance

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/challenge"
	"github.com/metril/certforge/internal/db/sqlcgen"
)

// DNSCredential is a stored provider credential; secrets are never exposed,
// only the names of stored secret fields.
type DNSCredential struct {
	ID, OrgID            uuid.UUID
	Name, ProviderCode   string
	Public               map[string]string
	StoredSecrets        []string
	UsedBy               int64
	CreatedAt, UpdatedAt time.Time
}

func (s *Store) credFromRow(ctx context.Context, r sqlcgen.DnsProviderCredential) (DNSCredential, map[string]string, error) {
	c := DNSCredential{ID: r.ID, OrgID: r.OrgID, Name: r.Name, ProviderCode: r.ProviderCode, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	if err := json.Unmarshal(r.PublicCfg, &c.Public); err != nil {
		return c, nil, err
	}
	var secret map[string]string
	if err := s.openJSON(ctx, r.SecretCfg, &secret); err != nil {
		return c, nil, err
	}
	c.StoredSecrets = challenge.SecretKeys(secret)
	n, err := s.q.CountDNSCredentialUsers(ctx, r.ID)
	if err != nil {
		return c, nil, err
	}
	ref, err := s.globalDefaultsReference(ctx, r.ID)
	if err != nil {
		return c, nil, err
	}
	if ref {
		n++
	}
	c.UsedBy = n
	return c, secret, nil
}

// splitErr maps challenge package sentinels to a 422 ValidationError by type,
// not by matching substrings of Error().
func splitErr(err error) error {
	switch {
	case errors.Is(err, challenge.ErrUnknownField), errors.Is(err, challenge.ErrUnknownProvider), errors.Is(err, challenge.ErrUnchangedOnCreate):
		return &ValidationError{Field: "config", Msg: err.Error()}
	default:
		return err
	}
}

// CreateDNSCredential validates cfg against the provider schema and stores it.
func (s *Store) CreateDNSCredential(ctx context.Context, orgID uuid.UUID, name, code string, cfg map[string]string) (DNSCredential, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return DNSCredential{}, &ValidationError{"name", "required"}
	}
	meta, ok := challenge.Lookup(code)
	if !ok {
		return DNSCredential{}, &ValidationError{"providerCode", "unknown DNS provider " + code}
	}
	pub, sec, err := challenge.SplitConfig(meta.Code, cfg)
	if err != nil {
		return DNSCredential{}, splitErr(err)
	}
	pubJSON, err := json.Marshal(pub)
	if err != nil {
		return DNSCredential{}, err
	}
	sealed, err := s.sealJSON(ctx, sec)
	if err != nil {
		return DNSCredential{}, err
	}
	row, err := s.q.CreateDNSCredential(ctx, sqlcgen.CreateDNSCredentialParams{OrgID: orgID, Name: name,
		ProviderCode: meta.Code, PublicCfg: pubJSON, SecretCfg: sealed})
	if err != nil {
		return DNSCredential{}, dbErr(err, "name")
	}
	c, _, err := s.credFromRow(ctx, row)
	return c, err
}

// UpdateDNSCredential replaces name and config; secret fields sent as
// challenge.Unchanged keep their stored value.
func (s *Store) UpdateDNSCredential(ctx context.Context, orgID, id uuid.UUID, name string, cfg map[string]string) (DNSCredential, error) {
	row, err := s.q.GetDNSCredential(ctx, sqlcgen.GetDNSCredentialParams{ID: id, OrgID: orgID})
	if err != nil {
		return DNSCredential{}, notFound(err)
	}
	var old map[string]string
	if err := s.openJSON(ctx, row.SecretCfg, &old); err != nil {
		return DNSCredential{}, err
	}
	pub, sec, err := challenge.MergeUpdate(row.ProviderCode, old, cfg)
	if err != nil {
		return DNSCredential{}, splitErr(err)
	}
	if name = strings.TrimSpace(name); name == "" {
		return DNSCredential{}, &ValidationError{"name", "required"}
	}
	pubJSON, err := json.Marshal(pub)
	if err != nil {
		return DNSCredential{}, err
	}
	sealed, err := s.sealJSON(ctx, sec)
	if err != nil {
		return DNSCredential{}, err
	}
	row, err = s.q.UpdateDNSCredential(ctx, sqlcgen.UpdateDNSCredentialParams{ID: id, OrgID: orgID, Name: name, PublicCfg: pubJSON, SecretCfg: sealed})
	if err != nil {
		return DNSCredential{}, dbErr(err, "name")
	}
	c, _, err := s.credFromRow(ctx, row)
	return c, err
}

// GetDNSCredential returns one credential without secrets.
func (s *Store) GetDNSCredential(ctx context.Context, orgID, id uuid.UUID) (DNSCredential, error) {
	row, err := s.q.GetDNSCredential(ctx, sqlcgen.GetDNSCredentialParams{ID: id, OrgID: orgID})
	if err != nil {
		return DNSCredential{}, notFound(err)
	}
	c, _, err := s.credFromRow(ctx, row)
	return c, err
}

// ListDNSCredentials returns the org's credentials without secrets.
func (s *Store) ListDNSCredentials(ctx context.Context, orgID uuid.UUID) ([]DNSCredential, error) {
	rows, err := s.q.ListDNSCredentials(ctx, orgID)
	if err != nil {
		return nil, err
	}
	out := make([]DNSCredential, 0, len(rows))
	for _, r := range rows {
		c, _, err := s.credFromRow(ctx, r)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// DeleteDNSCredential deletes an unreferenced credential.
func (s *Store) DeleteDNSCredential(ctx context.Context, orgID, id uuid.UUID) error {
	c, err := s.GetDNSCredential(ctx, orgID, id)
	if err != nil {
		return err
	}
	if c.UsedBy > 0 {
		return &InUseError{Users: c.UsedBy}
	}
	_, err = s.q.DeleteDNSCredential(ctx, sqlcgen.DeleteDNSCredentialParams{ID: id, OrgID: orgID})
	return err
}

// DNSCredentialConfig returns the credential and its full decrypted config.
func (s *Store) DNSCredentialConfig(ctx context.Context, orgID, id uuid.UUID) (DNSCredential, map[string]string, error) {
	row, err := s.q.GetDNSCredential(ctx, sqlcgen.GetDNSCredentialParams{ID: id, OrgID: orgID})
	if err != nil {
		return DNSCredential{}, nil, notFound(err)
	}
	c, secret, err := s.credFromRow(ctx, row)
	if err != nil {
		return c, nil, err
	}
	cfg := make(map[string]string, len(c.Public)+len(secret))
	for k, v := range c.Public {
		cfg[k] = v
	}
	for k, v := range secret {
		cfg[k] = v
	}
	return c, cfg, nil
}
