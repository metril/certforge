import { CircleCheck, CirclePlus, FileDiff, Pencil, Trash2, TriangleAlert } from 'lucide-react';
import { expect, it } from 'vitest';
import { actionTone } from './actions';

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
