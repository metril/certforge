package deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/delivery"
)

// PathConflictError reports that two live vault-kv server grants of one
// target would write the same KV document; the API maps it to 409.
type PathConflictError struct{ Msg string }

func (e *PathConflictError) Error() string { return e.Msg }

// OrgPathPrefix is the KV path prefix a vault-kv target of the org with
// slug may use unless its writer holds global delivery write.
func OrgPathPrefix(slug string) string { return "certforge/" + slug + "/" }

// CheckOrgPath refuses a vault-kv config whose path template does not start
// with the literal text certforge/<slug>/ ({org} may stand for the slug as
// the second segment). The prefix is checked on the template itself, never
// on a rendering, so a {name} or {cert} placeholder can never supply it, and
// empty, "." and ".." segments are refused outright.
func CheckOrgPath(raw json.RawMessage, slug string) error {
	var cfg VaultKVConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	cfg.fillDefaults()
	if _, err := renderPath(cfg.Path, slug, "00000000-0000-0000-0000-000000000000", "name"); err != nil {
		return err
	}
	segs := strings.Split(cfg.Path, "/")
	ok := len(segs) >= 3 && segs[0] == "certforge" && (segs[1] == slug || segs[1] == "{org}")
	for _, seg := range segs {
		if seg == "" || seg == "." || seg == ".." {
			ok = false
		}
	}
	if !ok {
		return fmt.Errorf("path must start with %q unless you hold global delivery write", OrgPathPrefix(slug))
	}
	return nil
}

// CheckServerGrantPaths renders (mount, path) for every live server grant
// of targetID and returns a *PathConflictError when two certificates would
// write the same KV document (SafeName-colliding names included, and every
// grant collides when the template has no {name} or {cert}). Nil for any
// target that is not vault-kv. The caller holds the target's row lock.
func CheckServerGrantPaths(ctx context.Context, q *sqlcgen.Queries, orgID, targetID uuid.UUID) error {
	t, err := q.GetDeployTarget(ctx, sqlcgen.GetDeployTargetParams{ID: targetID, OrgID: orgID})
	if err != nil {
		return err
	}
	if t.Type != TypeVaultKV {
		return nil
	}
	var cfg VaultKVConfig
	if err := json.Unmarshal(t.Config, &cfg); err != nil {
		return err
	}
	cfg.fillDefaults()
	org, err := q.GetOrg(ctx, orgID)
	if err != nil {
		return err
	}
	rows, err := q.ServerGrantViews(ctx, sqlcgen.ServerGrantViewsParams{OrgID: orgID, TargetID: &targetID})
	if err != nil {
		return err
	}
	owner := map[string]string{}
	for _, r := range rows {
		p, err := renderPath(cfg.Path, org.Slug, r.CertID.String(), delivery.SafeName(r.CertificateName))
		if err != nil {
			return err
		}
		k := cfg.Mount + "/" + p
		if other, ok := owner[k]; ok {
			return &PathConflictError{Msg: fmt.Sprintf("The grants for %q and %q on this target would both write %s; use a path with {cert} or {name}, or a different target.", other, r.CertificateName, k)}
		}
		owner[k] = r.CertificateName
	}
	return nil
}
