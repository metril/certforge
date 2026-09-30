import { expect, it } from 'vitest';
import type { RJSFSchema } from '@rjsf/utils';
import { advancedSchema, authMethodsOf, hasAdvancedValue, inferMethod, methodSchema } from './authMethods';

const schema = {
  type: 'object',
  required: ['CF_DNS_API_TOKEN'],
  'x-auth-methods': [
    { id: 'email-api-key', label: 'Email + API key', fields: ['CF_API_EMAIL', 'CF_API_KEY'], optional: ['CF_ZONE_API_TOKEN'] },
    { id: 'api-token', label: 'API token', fields: ['CF_DNS_API_TOKEN'], optional: ['CF_ZONE_API_TOKEN'] },
  ],
  properties: {
    CF_API_EMAIL: { type: 'string', 'x-group': 'credentials' },
    CF_API_KEY: { type: 'string', secret: true, 'x-group': 'credentials' },
    CF_DNS_API_TOKEN: { type: 'string', secret: true, 'x-group': 'credentials' },
    CF_ZONE_API_TOKEN: { type: 'string', secret: true, 'x-group': 'credentials' },
    CLOUDFLARE_API_KEY: { type: 'string', 'x-group': 'credentials', 'x-alias-of': 'CF_API_KEY' },
    CLOUDFLARE_TTL: { type: 'string', 'x-group': 'additional' },
    CLOUDFLARE_ALIAS: { type: 'string', 'x-group': 'additional', 'x-alias-of': 'CLOUDFLARE_TTL' },
    CLOUDFLARE_FILE: { type: 'string', 'x-group': 'additional', serverPath: true },
    ORPHAN_CRED: { type: 'string', 'x-group': 'credentials' },
  },
} as unknown as RJSFSchema;

const methods = authMethodsOf(schema);

it('parses methods and tolerates absence', () => {
  expect(methods.map((m) => m.id)).toEqual(['email-api-key', 'api-token']);
  expect(authMethodsOf({ type: 'object' })).toEqual([]);
});

it('infers complete, then most present, then first', () => {
  expect(inferMethod(methods, { CF_DNS_API_TOKEN: 't' })?.id).toBe('api-token');
  expect(inferMethod(methods, { CF_API_EMAIL: 'a', CF_API_KEY: 'k' })?.id).toBe('email-api-key');
  expect(inferMethod(methods, { CF_API_EMAIL: 'a' })?.id).toBe('email-api-key');
  expect(inferMethod(methods, {}, ['CF_API_KEY'])?.id).toBe('email-api-key');
  expect(inferMethod(methods, {})?.id).toBe('email-api-key');
  expect(inferMethod([], {})).toBeUndefined();
});

it('builds the method schema with required fields, optional after, no aliases', () => {
  const s = methodSchema(schema, methods[1]!);
  expect(Object.keys(s.properties!)).toEqual(['CF_DNS_API_TOKEN', 'CF_ZONE_API_TOKEN']);
  expect(s.required).toEqual(['CF_DNS_API_TOKEN']);
});

it('builds the advanced schema from additional, non-alias, unused, non-server fields', () => {
  expect(Object.keys(advancedSchema(schema).properties!)).toEqual(['CLOUDFLARE_TTL']);
  expect(hasAdvancedValue(schema, {})).toBe(false);
  expect(hasAdvancedValue(schema, { CLOUDFLARE_TTL: '300' })).toBe(true);
});
