// Package setup implements the first-run wizard and the break-glass
// bootstrap-admin command.
package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/metril/certforge/internal/audit"
	"github.com/metril/certforge/internal/authn"
	"github.com/metril/certforge/internal/authz"
	"github.com/metril/certforge/internal/config"
	"github.com/metril/certforge/internal/db/sqlcgen"
	"github.com/metril/certforge/internal/settings"
)

// CompletedKey marks a finished first-run setup in the settings table.
const CompletedKey = "setup.completed"

const lockKey int64 = 0x43460001

var (
	// ErrAlreadyComplete means setup already ran.
	ErrAlreadyComplete = errors.New("setup: already complete")
	// ErrInvalid wraps input validation failures.
	ErrInvalid = errors.New("setup: invalid input")
	// ErrSetupPending means bootstrap-admin was invoked before first-run
	// setup completed. No local admin may be created outside the setup
	// wizard, so bootstrap-admin only resets an existing one.
	ErrSetupPending = errors.New("setup: setup is pending; complete POST /api/v1/setup/complete before resetting the local admin")
)

var slugRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Input is the setup wizard form.
type Input struct {
	AdminPassword string
	OrgName       string
	OrgSlug       string
	BaseURL       string
}

// Result identifies what setup created.
type Result struct {
	AdminID uuid.UUID
	OrgID   uuid.UUID
}

// Service runs setup and admin password resets.
type Service struct {
	pool     *pgxpool.Pool
	aud      *audit.Auditor
	registry *settings.Registry
}

// New returns a Service. registry is used to validate the general section
// value (baseUrl) with the same JSON Schema the settings API enforces.
func New(pool *pgxpool.Pool, aud *audit.Auditor, registry *settings.Registry) *Service {
	return &Service{pool: pool, aud: aud, registry: registry}
}

// NeedsSetup reports whether first-run setup has not completed yet.
func (s *Service) NeedsSetup(ctx context.Context) (bool, error) {
	_, err := sqlcgen.New(s.pool).GetSetting(ctx, CompletedKey)
	if errors.Is(err, pgx.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return false, nil
}

// Complete performs first-run setup exactly once.
func (s *Service) Complete(ctx context.Context, in Input) (Result, error) {
	in.OrgName = strings.TrimSpace(in.OrgName)
	in.BaseURL = strings.TrimRight(strings.TrimSpace(in.BaseURL), "/")
	// Short-circuit a completed install before spending an argon2 hash or
	// taking the advisory lock; inLockedTx still re-checks under the lock
	// so a concurrent completer cannot race past this.
	if needs, err := s.NeedsSetup(ctx); err != nil {
		return Result{}, err
	} else if !needs {
		return Result{}, ErrAlreadyComplete
	}
	if err := s.validate(in); err != nil {
		return Result{}, err
	}
	hash, err := authn.HashPassword(in.AdminPassword)
	if err != nil {
		return Result{}, err
	}
	var res Result
	err = s.inLockedTx(ctx, func(q *sqlcgen.Queries) error {
		if _, err := q.GetSetting(ctx, CompletedKey); err == nil {
			return ErrAlreadyComplete
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		adminID, existed, err := upsertLocalAdmin(ctx, q, hash)
		if err != nil {
			return err
		}
		if existed {
			// A local admin row survived from a previous, uncompleted setup
			// attempt (or a restored database); Complete is about to
			// overwrite its password, so any session against the old one
			// must not remain valid.
			if err := q.DeleteUserSessions(ctx, adminID); err != nil {
				return err
			}
		}
		org, err := q.CreateOrg(ctx, sqlcgen.CreateOrgParams{Slug: in.OrgSlug, Name: in.OrgName})
		if err != nil {
			return fmt.Errorf("create org: %w", err)
		}
		general, err := json.Marshal(map[string]string{"baseUrl": in.BaseURL})
		if err != nil {
			return err
		}
		if err := q.UpsertSettingValue(ctx, sqlcgen.UpsertSettingValueParams{Key: settings.SectionKey("general"), Value: general}); err != nil {
			return err
		}
		done, err := json.Marshal(map[string]any{"completedAt": time.Now().UTC(), "orgId": org.ID})
		if err != nil {
			return err
		}
		if err := q.UpsertSettingValue(ctx, sqlcgen.UpsertSettingValueParams{Key: CompletedKey, Value: done}); err != nil {
			return err
		}
		res = Result{AdminID: adminID, OrgID: org.ID}
		return nil
	})
	if err != nil {
		return Result{}, err
	}
	// Setup already committed at this point: an audit-write failure must not
	// be reported as a failed setup (the caller would retry and hit
	// ErrAlreadyComplete). Log and continue instead.
	if err := s.aud.Record(ctx, audit.Event{
		Action: "setup.complete", ResourceType: "org", ResourceID: res.OrgID.String(), OrgID: &res.OrgID,
		ActorType: authn.KindUser, ActorID: res.AdminID.String(),
		Details: map[string]any{"orgSlug": in.OrgSlug, "baseUrl": in.BaseURL},
	}); err != nil {
		slog.Default().Error("setup: audit record failed", "action", "setup.complete", "err", err)
	}
	return res, nil
}

// SetAdminPassword resets the existing local admin's password, clears its
// disabled flag, ensures its global admin binding, and revokes its sessions.
// It refuses with ErrSetupPending while first-run setup has not completed:
// no local admin may be created outside the setup wizard, so bootstrap-admin
// (the only caller) may only reset one that setup already created.
func (s *Service) SetAdminPassword(ctx context.Context, password string) (uuid.UUID, error) {
	if len(password) < authn.MinPasswordLength {
		return uuid.Nil, fmt.Errorf("%w: password must be at least %d characters", ErrInvalid, authn.MinPasswordLength)
	}
	// Quick check before spending an argon2 hash; inLockedTx re-checks under
	// the lock so a concurrent setup completing cannot be raced past this.
	if needs, err := s.NeedsSetup(ctx); err != nil {
		return uuid.Nil, err
	} else if needs {
		return uuid.Nil, ErrSetupPending
	}
	hash, err := authn.HashPassword(password)
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = s.inLockedTx(ctx, func(q *sqlcgen.Queries) error {
		if _, err := q.GetSetting(ctx, CompletedKey); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrSetupPending
			}
			return err
		}
		var err error
		if id, _, err = upsertLocalAdmin(ctx, q, hash); err != nil {
			return err
		}
		return q.DeleteUserSessions(ctx, id)
	})
	if err != nil {
		return uuid.Nil, err
	}
	// The password reset already committed; an audit-write failure must not
	// be reported as a failed reset. Log and continue instead.
	if err := s.aud.Record(ctx, audit.Event{Action: "auth.local_admin_password_set", ResourceType: "user",
		ResourceID: id.String(), ActorType: "system", ActorID: "bootstrap-admin"}); err != nil {
		slog.Default().Error("setup: audit record failed", "action", "auth.local_admin_password_set", "err", err)
	}
	return id, nil
}

func (s *Service) inLockedTx(ctx context.Context, fn func(q *sqlcgen.Queries) error) error {
	// Explicit read committed (the Postgres default, stated here so the
	// post-lock re-check is guaranteed to see the previous winner's commit
	// rather than depending on an unstated default).
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", lockKey); err != nil {
		return err
	}
	if err := fn(sqlcgen.New(tx)); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// upsertLocalAdmin creates the local admin if none exists, or resets its
// password hash and clears its disabled flag if one does. existed reports
// which happened, so callers can revoke sessions only when resetting.
func upsertLocalAdmin(ctx context.Context, q *sqlcgen.Queries, hash string) (id uuid.UUID, existed bool, err error) {
	u, err := q.GetLocalAdmin(ctx)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if u, err = q.CreateLocalAdmin(ctx, hash); err != nil {
			return uuid.Nil, false, fmt.Errorf("create local admin: %w", err)
		}
	case err != nil:
		return uuid.Nil, false, err
	default:
		existed = true
		if err := q.SetLocalPasswordHash(ctx, sqlcgen.SetLocalPasswordHashParams{Hash: hash, ID: u.ID}); err != nil {
			return uuid.Nil, false, err
		}
		if err := q.SetUserDisabled(ctx, sqlcgen.SetUserDisabledParams{ID: u.ID, Disabled: false}); err != nil {
			return uuid.Nil, false, err
		}
	}
	if err := q.CreateRoleBinding(ctx, sqlcgen.CreateRoleBindingParams{SubjectType: "user", Subject: u.ID.String(), Role: authz.RoleAdmin}); err != nil {
		return uuid.Nil, false, err
	}
	return u.ID, existed, nil
}

func (s *Service) validate(in Input) error {
	var problems []string
	if len(in.AdminPassword) < authn.MinPasswordLength {
		problems = append(problems, fmt.Sprintf("adminPassword must be at least %d characters", authn.MinPasswordLength))
	} else if len(in.AdminPassword) > authn.MaxPasswordLength {
		problems = append(problems, fmt.Sprintf("adminPassword must not exceed %d bytes", authn.MaxPasswordLength))
	}
	if in.OrgName == "" || len(in.OrgName) > 100 {
		problems = append(problems, "orgName must be 1 to 100 characters")
	}
	if !slugRE.MatchString(in.OrgSlug) {
		problems = append(problems, "orgSlug must be lowercase letters, digits, and hyphens, starting with a letter or digit")
	}
	if err := config.ValidateBaseURL(in.BaseURL); err != nil {
		problems = append(problems, "baseUrl "+err.Error())
	} else if err := s.validateGeneral(in.BaseURL); err != nil {
		problems = append(problems, "baseUrl "+err.Error())
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}

// validateGeneral checks baseURL against the general section's JSON Schema,
// the same schema PUT /settings/general enforces. Complete must not accept a
// baseUrl that a later, unchanged PUT of the section would then reject with
// 422 (for example a scheme the schema's pattern requires lowercase).
func (s *Service) validateGeneral(baseURL string) error {
	sec, ok := s.registry.Section("general")
	if !ok {
		return errors.New("general settings section not registered")
	}
	raw, err := json.Marshal(map[string]string{"baseUrl": baseURL})
	if err != nil {
		return err
	}
	return sec.Validate(raw)
}
