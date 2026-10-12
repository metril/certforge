import { expect, it } from 'vitest';
import type { RJSFSchema } from '@rjsf/utils';
import { me, meWith, org, testSecretSchema, traefikSchema, vaultKvSchema } from '@/test/fixtures';
import { defaultRunsOn, forcedRunsOn, keyGateBlocks, locationChanged, needsKey, targetLocation, toTargetInput, typeHelpKey } from './targets';

it('forced runs-on for server and agent types', () => {
  expect(forcedRunsOn(vaultKvSchema)).toBe('server');
  expect(forcedRunsOn(traefikSchema)).toBe('agent');
});

it('either defaults to agent', () => {
  expect(forcedRunsOn(testSecretSchema)).toBeNull();
  expect(defaultRunsOn(testSecretSchema)).toBe('agent');
});

it('needsKey matrix', () => {
  expect(needsKey('never', {})).toBe(false);
  expect(needsKey('never', { includeKey: true })).toBe(false);
  expect(needsKey('optional', {})).toBe(false);
  expect(needsKey('optional', { includeKey: false })).toBe(false);
  expect(needsKey('optional', { includeKey: true })).toBe(true);
  expect(needsKey('always', {})).toBe(true);
  expect(needsKey('optional', { files: [{ content: 'fullchain' }, { content: 'key' }] })).toBe(true);
  expect(needsKey('optional', { files: [{ content: 'bundle' }] })).toBe(true);
  expect(needsKey('optional', { files: [{ content: 'custom' }] })).toBe(true);
  expect(needsKey('optional', { files: [{ content: 'fullchain' }, { content: 'cert' }] })).toBe(false);
  expect(needsKey(undefined, { includeKey: true })).toBe(false);
});

it('key gate only on server', () => {
  const operator = meWith([{ role: 'operator', orgId: org.id }]);
  expect(keyGateBlocks(operator, org.id, 'agent', 'always', {})).toBe(false);
  expect(keyGateBlocks(operator, org.id, 'server', 'always', {})).toBe(true);
  expect(keyGateBlocks(me, org.id, 'server', 'always', {})).toBe(false);
  expect(keyGateBlocks(operator, org.id, 'server', 'never', {})).toBe(false);
});

it('typeHelpKey falls back to target.type', () => {
  expect(typeHelpKey('vault-kv')).toBe('target.vaultKv');
  expect(typeHelpKey('traefik')).toBe('target.type');
  expect(typeHelpKey('test-secret')).toBe('target.type');
});

it('location prefers url then dir then path', () => {
  expect(targetLocation({ url: 'https://a.test', dir: '/etc/a', path: 'p' })).toBe('https://a.test');
  expect(targetLocation({ dir: '/etc/a', path: 'p' })).toBe('/etc/a');
  expect(targetLocation({ path: 'p' })).toBe('p');
  expect(targetLocation({})).toBe('–');
});

it('input omits runsOn on update', () => {
  const schema = traefikSchema.schema as RJSFSchema;
  const draft = { name: ' edge ', type: 'traefik', runsOn: 'agent' as const, config: { dir: '/etc/traefik/dynamic' } };
  expect(toTargetInput(draft, schema, [], true)).toEqual({ name: 'edge', type: 'traefik', runsOn: 'agent', config: { dir: '/etc/traefik/dynamic' } });
  const update = toTargetInput(draft, schema, [], false);
  expect(update).not.toHaveProperty('runsOn');
  expect(update).toEqual({ name: 'edge', type: 'traefik', config: { dir: '/etc/traefik/dynamic' } });
});

it('locationChanged covers every field the server gates for credential-backed targets', () => {
  const schema: RJSFSchema = {
    type: 'object',
    properties: { host: { type: 'string' }, port: { type: 'integer', default: 22 }, sshPort: { type: 'integer' }, hostKey: { type: 'string' }, files: { type: 'string' } },
  };
  const base = { host: 'a.example', hostKey: 'ssh-ed25519 AAAA', sshPort: 22 };
  expect(locationChanged(schema, base, { ...base })).toBe(false);
  expect(locationChanged(schema, base, { ...base, files: 'x' })).toBe(false);
  expect(locationChanged(schema, base, { ...base, host: 'b.example' })).toBe(true);
  expect(locationChanged(schema, base, { ...base, port: 2222 })).toBe(true);
  expect(locationChanged(schema, base, { ...base, sshPort: 2222 })).toBe(true);
  expect(locationChanged(schema, base, { ...base, hostKey: 'ssh-ed25519 BBBB' })).toBe(true);
});
