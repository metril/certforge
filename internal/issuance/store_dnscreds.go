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

// credFromRow builds the credential with its decrypted secret map and a
// per-row UsedBy; ListDNSCredentials uses credListEntry instead.
func (s *Store) credFromRow(ctx context.Context, r sqlcgen.DnsProviderCredential) (DNSCredential, map[string]string, error) {
	c := DNSCredential{ID: r.ID, OrgID: r.OrgID, Name: r.Name, ProviderCode: r.ProviderCode, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	if err := json.Unmarshal(r.PublicCfg, &c.Public); err != nil {
		return c, nil, err
	}
	var secret map[string]string
	if err := s.openJSON(ctx, r.SecretCfg, &secret); err != nil {
		return c, nil, err
	}
	c.Public = challenge.CanonicalizeStored(r.ProviderCode, c.Public)
	secret = challenge.CanonicalizeStored(r.ProviderCode, secret)
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

// credListEntry is credFromRow for a listing: the stored secret names come
// from the plaintext column (opening the sealed value only for a row from
// before it existed) and UsedBy is filled in by the caller from one batched
// count.
func (s *Store) credListEntry(ctx context.Context, r sqlcgen.DnsProviderCredential) (DNSCredential, error) {
	c := DNSCredential{ID: r.ID, OrgID: r.OrgID, Name: r.Name, ProviderCode: r.ProviderCode, CreatedAt: r.CreatedAt, UpdatedAt: r.UpdatedAt}
	if err := json.Unmarshal(r.PublicCfg, &c.Public); err != nil {
		return c, err
	}
	c.Public = challenge.CanonicalizeStored(r.ProviderCode, c.Public)
	c.StoredSecrets = r.StoredSecretKeys
	if len(c.StoredSecrets) == 0 && len(r.SecretCfg) > 0 {
		var secret map[string]string
		if err := s.openJSON(ctx, r.SecretCfg, &secret); err != nil {
			return c, err
		}
		c.StoredSecrets = challenge.SecretKeys(challenge.CanonicalizeStored(r.ProviderCode, secret))
	}
	return c, nil
}

// splitErr maps challenge package sentinels to a 422 ValidationError by type,
// not by matching substrings of Error().
func splitErr(err error) error {
	switch {
	case errors.Is(err, challenge.ErrUnknownField), errors.Is(err, challenge.ErrUnknownProvider),
		errors.Is(err, challenge.ErrUnchangedOnCreate), errors.Is(err, challenge.ErrServerPath),
		errors.Is(err, challenge.ErrNoAuthMethod), errors.Is(err, challenge.ErrAliasConflict):
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
	if meta.Unsupported {
		return DNSCredential{}, &ValidationError{"providerCode", meta.Name + " is not supported yet: " + meta.UnsupportedReason}
	}
	pub, sec, err := challenge.SplitConfig(meta.Code, cfg)
	if err != nil {
		return DNSCredential{}, splitErr(err)
	}
	if err := checkAmbient(ctx, meta.Code, pub, sec); err != nil {
		return DNSCredential{}, err
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
		ProviderCode: meta.Code, PublicCfg: pubJSON, SecretCfg: sealed,
		StoredSecretKeys: challenge.SecretKeys(challenge.CanonicalizeStored(meta.Code, sec))})
	if err != nil {
		return DNSCredential{}, dbErr(err, "name")
	}
	c, _, err := s.credFromRow(ctx, row)
	return c, err
}

// UpdateDNSCredential replaces name and config; secret fields sent as
// challenge.Unchanged keep their stored value, unless the update also
// changes a public field, in which case every secret must be re-entered (a
// 422 ValidationError) rather than silently carried over to the changed
// setting — the old secret would otherwise apply to a new connection
// setting (for example, a stored token sent to a changed endpoint URL)
// without the caller ever having re-entered it. changedPublic lists the
// public keys the update changed, for the caller's audit record.
func (s *Store) UpdateDNSCredential(ctx context.Context, orgID, id uuid.UUID, name string, cfg map[string]string) (DNSCredential, []string, error) {
	row, err := s.q.GetDNSCredential(ctx, sqlcgen.GetDNSCredentialParams{ID: id, OrgID: orgID})
	if err != nil {
		return DNSCredential{}, nil, notFound(err)
	}
	if meta, ok := challenge.Lookup(row.ProviderCode); ok && meta.Unsupported {
		return DNSCredential{}, nil, &ValidationError{"providerCode", meta.Name + " is not supported yet: " + meta.UnsupportedReason}
	}
	var oldPublic map[string]string
	if err := json.Unmarshal(row.PublicCfg, &oldPublic); err != nil {
		return DNSCredential{}, nil, err
	}
	var oldSecret map[string]string
	if err := s.openJSON(ctx, row.SecretCfg, &oldSecret); err != nil {
		return DNSCredential{}, nil, err
	}
	pub, sec, changedPublic, reusedSecret, err := challenge.MergeUpdate(row.ProviderCode, oldPublic, oldSecret, cfg)
	if err != nil {
		return DNSCredential{}, nil, splitErr(err)
	}
	if err := checkAmbient(ctx, row.ProviderCode, pub, sec); err != nil {
		return DNSCredential{}, nil, err
	}
	if len(changedPublic) > 0 && reusedSecret {
		return DNSCredential{}, nil, &ValidationError{Field: "config", Msg: "secrets must be re-entered when connection settings change"}
	}
	if name = strings.TrimSpace(name); name == "" {
		return DNSCredential{}, nil, &ValidationError{"name", "required"}
	}
	pubJSON, err := json.Marshal(pub)
	if err != nil {
		return DNSCredential{}, nil, err
	}
	sealed, err := s.sealJSON(ctx, sec)
	if err != nil {
		return DNSCredential{}, nil, err
	}
	row, err = s.q.UpdateDNSCredential(ctx, sqlcgen.UpdateDNSCredentialParams{ID: id, OrgID: orgID, Name: name, PublicCfg: pubJSON, SecretCfg: sealed,
		StoredSecretKeys: challenge.SecretKeys(challenge.CanonicalizeStored(row.ProviderCode, sec))})
	if err != nil {
		return DNSCredential{}, nil, dbErr(err, "name")
	}
	c, _, err := s.credFromRow(ctx, row)
	return c, changedPublic, err
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

// DNSCredentialSecret returns one decrypted secret field of a credential. It
// looks only in the secret map, so a public field never resolves here; a
// missing credential or an unstored field is a not-found error.
func (s *Store) DNSCredentialSecret(ctx context.Context, orgID, id uuid.UUID, field string) (string, error) {
	row, err := s.q.GetDNSCredential(ctx, sqlcgen.GetDNSCredentialParams{ID: id, OrgID: orgID})
	if err != nil {
		return "", notFound(err)
	}
	_, secret, err := s.credFromRow(ctx, row)
	if err != nil {
		return "", err
	}
	v, ok := secret[field]
	if !ok {
		return "", ErrNotFound
	}
	return v, nil
}

// ListDNSCredentials returns the org's credentials without secrets.
func (s *Store) ListDNSCredentials(ctx context.Context, orgID uuid.UUID) ([]DNSCredential, error) {
	rows, err := s.q.ListDNSCredentials(ctx, orgID)
	if err != nil {
		return nil, err
	}
	counts, err := s.q.CountDNSCredentialUsersByOrg(ctx, orgID)
	if err != nil {
		return nil, err
	}
	used := make(map[uuid.UUID]int64, len(counts))
	for _, n := range counts {
		used[n.ID] = n.Users
	}
	// The global defaults are read once per call, not per row.
	g, err := s.GlobalDefaults(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]DNSCredential, 0, len(rows))
	for _, r := range rows {
		c, err := s.credListEntry(ctx, r)
		if err != nil {
			return nil, err
		}
		c.UsedBy = used[r.ID]
		if defaultsReference(g, r.ID) {
			c.UsedBy++
		}
		out = append(out, c)
	}
	return out, nil
}

// DeleteDNSCredential deletes an unreferenced credential. The row is FOR
// UPDATE-locked for the whole count-then-delete (in one transaction), which
// blocks a concurrent org or global issuance-defaults write that takes a FOR
// KEY SHARE lock on the same row before validating and writing
// (validateDefaultsTx/validateRulesOrgTx, ValidateGlobalDefaultsTx); the
// reference checks (CountDNSCredentialUsers, globalDefaultsReferenceTx) run
// after the lock is held, in the same transaction. Certificate writes take
// this same FOR KEY SHARE lock too (store_certs.go's LockDNSCredentialKeyShare
// calls), so a concurrent certificate create/update referencing this
// credential is protected by it exactly like the org/global defaults case
// above: CountDNSCredentialUsers counts certificates as users, and now races
// a lock against their writer as well.
func (s *Store) DeleteDNSCredential(ctx context.Context, orgID, id uuid.UUID) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	q := s.q.WithTx(tx)
	if _, err := q.LockDNSCredential(ctx, sqlcgen.LockDNSCredentialParams{ID: id, OrgID: orgID}); err != nil {
		return notFound(err)
	}
	n, err := q.CountDNSCredentialUsers(ctx, id)
	if err != nil {
		return err
	}
	ref, err := s.globalDefaultsReferenceTx(ctx, tx, id)
	if err != nil {
		return err
	}
	if ref {
		n++
	}
	if n > 0 {
		return &InUseError{Users: n}
	}
	if _, err := q.DeleteDNSCredential(ctx, sqlcgen.DeleteDNSCredentialParams{ID: id, OrgID: orgID}); err != nil {
		return err
	}
	return tx.Commit(ctx)
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

type ambientKey struct{}

// WithAmbientCredentials marks ctx as belonging to a caller allowed to store
// DNS credentials that use the server's own cloud identity (ambient auth,
// AWS_ASSUME_ROLE_ARN, AWS_PROFILE): a global settings:write holder. Without
// it Create/UpdateDNSCredential reject such configs.
func WithAmbientCredentials(ctx context.Context) context.Context {
	return context.WithValue(ctx, ambientKey{}, true)
}

func checkAmbient(ctx context.Context, code string, pub, sec map[string]string) error {
	if ok, _ := ctx.Value(ambientKey{}).(bool); ok {
		return nil
	}
	if err := challenge.CheckNoAmbient(code, pub, sec); err != nil {
		return &ValidationError{Field: "config", Msg: err.Error()}
	}
	return nil
}
