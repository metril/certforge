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
-- "another admin exists" answer. Locks both the user row and its binding
-- row: under READ COMMITTED, only a row an UPDATE actually touches is
-- re-checked by a concurrent locker, so locking `u` alone never blocks a
-- concurrent DELETE of `rb` (the binding row itself) -- two guarded
-- operations could both pass and leave zero enabled global admins.
SELECT u.* FROM users u
JOIN role_bindings rb ON rb.subject_type = 'user' AND rb.subject = u.id::text
WHERE rb.role = 'admin' AND rb.org_id IS NULL
ORDER BY u.id, rb.id
FOR UPDATE OF u, rb;

-- name: ListRoleBindingsWithLabels :many
SELECT rb.id, rb.subject_type, rb.subject, rb.role, rb.org_id, rb.created_at,
       COALESCE(u.display_name, k.name, '')::text AS subject_label
FROM role_bindings rb
LEFT JOIN users u ON rb.subject_type = 'user' AND u.id::text = rb.subject
LEFT JOIN api_keys k ON rb.subject_type = 'apikey' AND k.id::text = rb.subject
WHERE rb.site_id IS NULL
ORDER BY rb.created_at, rb.id;

-- name: InsertRoleBinding :one
INSERT INTO role_bindings (subject_type, subject, role, org_id) VALUES ($1, $2, $3, $4) RETURNING *;

-- name: GetRoleBinding :one
SELECT * FROM role_bindings WHERE id = $1;

-- name: DeleteRoleBinding :exec
DELETE FROM role_bindings WHERE id = $1;
