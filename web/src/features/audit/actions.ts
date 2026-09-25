import type { ComboOption } from '@/components/Combobox';

// Actions the server records (internal/api, internal/issuance, internal/setup,
// internal/authn). B5: includes the legacy auth.* actions alongside session.*.
export const AUDIT_ACTIONS = [
  'acme_account.create', 'acme_account.delete', 'api_key.create', 'api_key.revoke', 'audit.export',
  'auth.local_admin_password_set', 'auth.login', 'auth.login_failed', 'auth.logout', 'ca.create', 'ca.delete',
  'ca.update', 'certificate.create', 'certificate.delete', 'certificate.key_exported', 'certificate.manual_dns_confirmed',
  'certificate.renew', 'certificate.update', 'dns_credential.create', 'dns_credential.delete', 'dns_credential.test',
  'dns_credential.update', 'issuance_defaults.update', 'org.create', 'org.delete', 'org.update', 'role_binding.create',
  'role_binding.delete', 'session.login', 'session.login_failed', 'session.logout', 'session.revoked',
  'settings.update', 'setup.complete', 'site.create', 'site.delete', 'site.update', 'user.update',
] as const;

export const AUDIT_RESOURCE_TYPES = [
  'acme_account', 'api_key', 'audit', 'ca', 'certificate', 'certificate_version', 'dns_credential',
  'issuance_defaults', 'org', 'role_binding', 'settings', 'site', 'user',
] as const;

export const actionLabel = (a: string) => (a.endsWith('.') ? `${a}*` : a);

/** Every "group." prefix first, then each action. */
export function actionOptions(): ComboOption[] {
  const groups = [...new Set(AUDIT_ACTIONS.map((a) => a.slice(0, a.indexOf('.') + 1)))];
  return [...groups.map((g) => ({ value: g, label: actionLabel(g) })), ...AUDIT_ACTIONS.map((a) => ({ value: a, label: a }))];
}
