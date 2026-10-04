import { CircleCheck, CirclePlus, FileDiff, Pencil, Trash2, TriangleAlert } from 'lucide-react';
import { expect, it } from 'vitest';
import { actionTone, AUDIT_ACTIONS, AUDIT_RESOURCE_TYPES } from './actions';

it.each([
  ['session.login_failed', 'failed', TriangleAlert],
  ['role_binding.delete', 'failed', Trash2],
  ['api_key.revoke', 'failed', Trash2],
  ['org.create', 'valid', CirclePlus],
  ['session.login', 'valid', CircleCheck],
  ['certificate.renew', 'valid', CircleCheck],
  ['setup.complete', 'valid', CircleCheck],
  ['certificate.manual_dns_confirmed', 'valid', CircleCheck],
  ['certificate.update', 'neutral', Pencil],
  ['dns_credential.test', 'neutral', Pencil],
  ['deployment.drift', 'drift', FileDiff],
  ['deployment.failed', 'failed', TriangleAlert],
  ['deployment.ok', 'valid', CircleCheck],
  ['client.enrolled', 'valid', CircleCheck],
  ['client.revoke', 'failed', Trash2],
  ['grant.create', 'valid', CirclePlus],
])('actionTone(%s) is %s', (action, tone, icon) => {
  expect(actionTone(action)).toEqual({ tone, icon });
});

// Snapshot of the server's audit actions and resource types (grep `Action:` /
// `ResourceType:` in internal/); the filter pickers must offer every one.
const SERVER_ACTIONS = [
  'ca.rotate', 'certificate.import', 'certificate.revoked', 'channel.create', 'channel.update', 'channel.delete', 'channel.test',
  'monitor.create', 'monitor.update', 'monitor.delete', 'monitor.check', 'backup.created', 'backup.failed',
  'kek.rewrap_started', 'kek.rewrap_finished', 'smtp.test', 'dns_credential.secret_revealed', 'acme_account.create',
  'agent_ca.rotate', 'api_key.revoke', 'audit.export', 'certificate.delete', 'certificate.renew', 'client.reenroll',
  'deployment.ok', 'grant.redeploy', 'hook.run', 'issuance_defaults.update', 'role_binding.delete', 'session.revoked',
  'settings.update', 'setup.complete', 'site.delete', 'user.update',
];
const SERVER_RESOURCES = [
  'acme_account', 'agent_ca', 'api_key', 'audit', 'backup', 'ca', 'certificate', 'certificate_version', 'channel', 'client',
  'deploy_target', 'dns_credential', 'grant', 'hook', 'issuance_defaults', 'kek', 'layout', 'monitor', 'org', 'role_binding',
  'session', 'settings', 'site', 'user',
];

it('offers every server audit action and resource type', () => {
  expect(SERVER_ACTIONS.filter((a) => !(AUDIT_ACTIONS as readonly string[]).includes(a))).toEqual([]);
  expect(SERVER_RESOURCES.filter((r) => !(AUDIT_RESOURCE_TYPES as readonly string[]).includes(r))).toEqual([]);
});
