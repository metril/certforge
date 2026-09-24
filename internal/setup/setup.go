// Package setup implements the first-run wizard and the break-glass
// bootstrap-admin command.
package setup

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	pool *pgxpool.Pool
	aud  *audit.Auditor
}

// New returns a Service.
func New(pool *pgxpool.Pool, aud *audit.Auditor) *Service { return &Service{pool: pool, aud: aud} }

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
	if err := in.validate(); err != nil {
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
		adminID, err := upsertLocalAdmin(ctx, q, hash)
		if err != nil {
			return err
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
	err = s.aud.Record(ctx, audit.Event{
		Action: "setup.complete", ResourceType: "org", ResourceID: res.OrgID.String(), OrgID: &res.OrgID,
		ActorType: authn.KindUser, ActorID: res.AdminID.String(),
		Details: map[string]any{"orgSlug": in.OrgSlug, "baseUrl": in.BaseURL},
	})
	if err != nil {
		return res, fmt.Errorf("setup: audit: %w", err)
	}
	return res, nil
}

// SetAdminPassword creates or resets the local admin, ensures its global
// admin binding, and revokes its sessions.
func (s *Service) SetAdminPassword(ctx context.Context, password string) (uuid.UUID, error) {
	if len(password) < authn.MinPasswordLength {
		return uuid.Nil, fmt.Errorf("%w: password must be at least %d characters", ErrInvalid, authn.MinPasswordLength)
	}
	hash, err := authn.HashPassword(password)
	if err != nil {
		return uuid.Nil, err
	}
	var id uuid.UUID
	err = s.inLockedTx(ctx, func(q *sqlcgen.Queries) error {
		var err error
		if id, err = upsertLocalAdmin(ctx, q, hash); err != nil {
			return err
		}
		return q.DeleteUserSessions(ctx, id)
	})
	if err != nil {
		return uuid.Nil, err
	}
	err = s.aud.Record(ctx, audit.Event{Action: "auth.local_admin_password_set", ResourceType: "user",
		ResourceID: id.String(), ActorType: "system", ActorID: "bootstrap-admin"})
	if err != nil {
		return id, fmt.Errorf("setup: audit: %w", err)
	}
	return id, nil
}

func (s *Service) inLockedTx(ctx context.Context, fn func(q *sqlcgen.Queries) error) error {
	tx, err := s.pool.Begin(ctx)
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

func upsertLocalAdmin(ctx context.Context, q *sqlcgen.Queries, hash string) (uuid.UUID, error) {
	u, err := q.GetLocalAdmin(ctx)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		if u, err = q.CreateLocalAdmin(ctx, hash); err != nil {
			return uuid.Nil, fmt.Errorf("create local admin: %w", err)
		}
	case err != nil:
		return uuid.Nil, err
	default:
		if err := q.SetLocalPasswordHash(ctx, sqlcgen.SetLocalPasswordHashParams{Hash: hash, ID: u.ID}); err != nil {
			return uuid.Nil, err
		}
	}
	err = q.CreateRoleBinding(ctx, sqlcgen.CreateRoleBindingParams{SubjectType: "user", Subject: u.ID.String(), Role: authz.RoleAdmin})
	if err != nil {
		return uuid.Nil, err
	}
	return u.ID, nil
}

func (in Input) validate() error {
	var problems []string
	if len(in.AdminPassword) < authn.MinPasswordLength {
		problems = append(problems, fmt.Sprintf("adminPassword must be at least %d characters", authn.MinPasswordLength))
	}
	if in.OrgName == "" || len(in.OrgName) > 100 {
		problems = append(problems, "orgName must be 1 to 100 characters")
	}
	if !slugRE.MatchString(in.OrgSlug) {
		problems = append(problems, "orgSlug must be lowercase letters, digits, and hyphens, starting with a letter or digit")
	}
	if err := config.ValidateBaseURL(in.BaseURL); err != nil {
		problems = append(problems, "baseUrl "+err.Error())
	}
	if len(problems) > 0 {
		return fmt.Errorf("%w: %s", ErrInvalid, strings.Join(problems, "; "))
	}
	return nil
}
