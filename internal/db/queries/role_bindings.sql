-- name: CreateRoleBinding :exec
INSERT INTO role_bindings (subject_type, subject, role, org_id, site_id)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT DO NOTHING;

-- name: ListRoleBindingsForUser :many
SELECT * FROM role_bindings WHERE subject_type = 'user' AND subject = $1 ORDER BY created_at, id;

-- name: ListRoleBindingsForPrincipal :many
SELECT * FROM role_bindings
WHERE (subject_type = 'user' AND subject = sqlc.arg(user_id)::text)
   OR (subject_type = 'oidc_group' AND subject = ANY(sqlc.arg(groups)::text[]))
ORDER BY created_at, id;

-- name: LockGlobalAdminUsers :many
-- Users holding a global (org-less) admin role binding, locked in a stable
-- order so concurrent callers serialize instead of both reading a stale
-- "another admin exists" answer.
SELECT u.* FROM users u
JOIN role_bindings rb ON rb.subject_type = 'user' AND rb.subject = u.id::text
WHERE rb.role = 'admin' AND rb.org_id IS NULL
ORDER BY u.id
FOR UPDATE OF u;
