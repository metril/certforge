import { expect, it } from 'vitest';
import type { RJSFSchema } from '@rjsf/utils';
import { UNCHANGED } from '@/api/types';
import { testSecretSchema } from '@/test/fixtures';
import { configSnapshot, storedSecretsFor, stripSecretDefaults, withStoredSentinels } from './secretForm';

const schema = testSecretSchema.schema as RJSFSchema;

it('fills only missing stored secrets', () => {
  expect(withStoredSentinels(schema, { url: 'https://a.test' }, ['token'])).toEqual({
    url: 'https://a.test',
    token: UNCHANGED,
  });
});

it('keeps empty string for remove', () => {
  expect(withStoredSentinels(schema, { url: 'https://a.test', token: '' }, ['token'])).toEqual({
    url: 'https://a.test',
    token: '',
  });
});

it('ignores non-secret stored keys', () => {
  // "url" isn't a secret field; listing it as stored must not sentinel it.
  expect(withStoredSentinels(schema, {}, ['url'])).toEqual({});
});

it('storedSecretsFor empty on type change', () => {
  expect(storedSecretsFor({ type: 'test-secret', storedSecrets: ['token'] }, 'traefik')).toEqual([]);
  expect(storedSecretsFor(undefined, 'traefik')).toEqual([]);
  expect(storedSecretsFor({ type: 'test-secret', storedSecrets: ['token'] }, 'test-secret')).toEqual(['token']);
});

it('snapshot equal before and after sentinel', () => {
  const before = configSnapshot(schema, { url: 'https://a.test' }, ['token']);
  const after = configSnapshot(schema, { url: 'https://a.test', token: UNCHANGED }, ['token']);
  expect(before).toBe(after);
});

it('strip secret defaults moves default to placeholder', () => {
  const stripped = stripSecretDefaults(schema);
  const token = stripped.properties!.token as RJSFSchema;
  expect(token.default).toBeUndefined();
  expect(token.examples).toEqual(['default-token']);
  // Non-secret properties are untouched.
  expect((stripped.properties!.url as RJSFSchema).title).toBe('URL');
});
