# 0007: Role bindings and API keys

Status: accepted (Phase 2)

## Context
Access is role-based, global or per org (docs/design.md, Auth and authorization). Humans come from OIDC with groups; machines use API keys.

## Decision
- One table, `role_bindings(subject_type, subject, role, org_id, site_id)`, is the only source of grants. Subjects: a user id, an OIDC group name (matched against the groups from the user's last login), or an API key id. Settings → Authentication's group mappings are oidc_group bindings, not a separate settings field.
- `authz.Can(p, action, orgID)` evaluates bindings; the principal is rebuilt on every request, so a binding change or a disable takes effect immediately.
- Site-scoped bindings stay unmodelled: sites are a filter; Phase 3 wires them to clients.
- API keys: `cf_<12 hex prefix>_<32-byte secret>`, SHA-256 stored. A key acts as its creator, re-evaluated on each request, narrowed by scopes, its org, and any bindings whose subject is the key. Scopes are intersected with the creator's permissions at creation. Keys cannot create keys and need no CSRF token.
- The last global admin binding held by a user cannot be deleted; deletes lock all such bindings first.
- Creating or deleting a role binding is authorized per subject type, not uniformly by bindings:write in the request's `orgId` (controller rulings C9/D1):
  - A `user` subject needs `bindings:write` in the binding's org (globally when omitted); an org-admin may only bind users within its own org.
  - An `oidc_group` subject always needs `bindings:write` globally, whatever org the binding targets. Group mappings are admin-only — an org-admin cannot create or delete one even in its own org — because a group binding changes who is trusted at every org an admin later adds that group to, not just the one named on the request.
  - An `apikey` subject needs `apikeys:write` at the key's own scope (global for a global key, the key's org for an org-scoped key) instead of `bindings:write`. This keeps API key permission management under the same action a caller already needs to manage the key itself, and stops an org-admin from reaching into a global key's authority through the bindings endpoint.

## Consequences
Disabling a user also disables every key they created. A key never outlives its creator's authority. An org-admin's practical reach over bindings is narrower than a first read of "everything within its org" suggests: OIDC group bindings and bindings on keys outside its org stay out of reach, both gated on their own actions rather than the org-scoped `bindings:write` an org-admin otherwise holds.
