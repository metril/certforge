-- name: CreateRoleBinding :exec
INSERT INTO role_bindings (subject_type, subject, role, org_id, site_id)
VALUES ($1, $2, $3, $4, $5)
ON CONFLICT DO NOTHING;

-- name: ListRoleBindingsForUser :many
SELECT * FROM role_bindings WHERE subject_type = 'user' AND subject = $1 ORDER BY created_at, id;
