import { CircleCheck, CirclePlus, FileDiff, Pencil, Trash2, TriangleAlert, type LucideIcon } from 'lucide-react';
import type { ComboOption } from '@/components/Combobox';
import type { Tone } from '@/lib/status';

// Actions the server records (internal/api, internal/issuance, internal/setup,
// internal/authn, internal/agent). B5: includes the legacy auth.* actions
// alongside session.*. Phase 3 adds client/grant/deployment/layout/
// deploy_target/hook/agent_ca actions.
export const AUDIT_ACTIONS = [
  'acme_account.create', 'acme_account.delete', 'agent_ca.retire', 'agent_ca.rotate', 'api_key.create',
  'api_key.revoke', 'audit.export', 'auth.local_admin_password_set', 'auth.login', 'auth.login_failed',
  'auth.logout', 'backup.created', 'backup.failed', 'ca.create', 'ca.delete', 'ca.rotate', 'ca.update',
  'certificate.create', 'certificate.delete', 'certificate.import', 'certificate.key_exported',
  'certificate.manual_dns_confirmed', 'certificate.renew', 'certificate.revoked', 'certificate.update',
  'channel.create', 'channel.delete', 'channel.test', 'channel.update', 'client.cert_renewed',
  'client.create', 'client.delete', 'client.enrolled', 'client.reenroll', 'client.revoke', 'client.update',
  'deploy_target.create', 'deploy_target.delete', 'deploy_target.update', 'deployment.drift',
  'deployment.failed', 'deployment.ok', 'dns_credential.create', 'dns_credential.delete',
  'dns_credential.secret_revealed', 'dns_credential.test', 'dns_credential.update', 'grant.bundle_fetched',
  'grant.create', 'grant.delete', 'grant.redeploy', 'grant.update', 'hook.create', 'hook.delete', 'hook.run',
  'hook.update', 'issuance_defaults.update', 'kek.rewrap_finished', 'kek.rewrap_started', 'layout.create',
  'layout.delete', 'layout.update', 'monitor.check', 'monitor.create', 'monitor.delete', 'monitor.update',
  'org.create', 'org.delete', 'org.update', 'role_binding.create', 'role_binding.delete', 'session.login',
  'session.login_failed', 'session.logout', 'session.revoked', 'settings.update', 'setup.complete',
  'site.create', 'site.delete', 'site.update', 'smtp.test', 'user.update',
] as const;

export const AUDIT_RESOURCE_TYPES = [
  'acme_account', 'agent_ca', 'api_key', 'audit', 'backup', 'ca', 'certificate', 'certificate_version',
  'channel', 'client', 'deploy_target', 'dns_credential', 'grant', 'hook', 'issuance_defaults', 'kek',
  'layout', 'monitor', 'org', 'role_binding', 'session', 'settings', 'site', 'user',
] as const;

export const actionLabel = (a: string) => (a.endsWith('.') ? `${a}*` : a);

/** Tone/icon for the Overview's Recent activity chip: a quick visual cue by
 * verb family, not a full per-action taxonomy. */
export function actionTone(action: string): { tone: Tone; icon: LucideIcon } {
  if (action === 'deployment.drift') return { tone: 'drift', icon: FileDiff };
  if (action.endsWith('.failed')) return { tone: 'failed', icon: TriangleAlert };
  if (action === 'deployment.ok' || action === 'client.enrolled') return { tone: 'valid', icon: CircleCheck };
  if (action.endsWith('_failed')) return { tone: 'failed', icon: TriangleAlert };
  if (action.includes('delete') || action.includes('revoke')) return { tone: 'failed', icon: Trash2 };
  if (action.includes('create')) return { tone: 'valid', icon: CirclePlus };
  if (action.includes('login') || action.includes('renew') || action.includes('complete') || action.includes('confirmed')) return { tone: 'valid', icon: CircleCheck };
  return { tone: 'neutral', icon: Pencil };
}

/** Every "group." prefix first, then each action. */
export function actionOptions(): ComboOption[] {
  const groups = [...new Set(AUDIT_ACTIONS.map((a) => a.slice(0, a.indexOf('.') + 1)))];
  return [...groups.map((g) => ({ value: g, label: actionLabel(g) })), ...AUDIT_ACTIONS.map((a) => ({ value: a, label: a }))];
}
