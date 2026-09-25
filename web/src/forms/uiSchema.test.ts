import { expect, it } from 'vitest';
import type { RJSFSchema } from '@rjsf/utils';
import { UNCHANGED } from '@/api/types';
import { cloudflare, route53 } from '@/test/fixtures';
import { buildUiSchema, secretKeys, withSecretSentinels } from './uiSchema';

const schema = cloudflare.schema as RJSFSchema;

it('finds secret fields', () => {
  expect(secretKeys(schema)).toEqual(['CF_DNS_API_TOKEN', 'CF_ZONE_API_TOKEN']);
});

it('routes each secret to the secret widget with its own stored flag, and hides the submit button', () => {
  const ui = buildUiSchema(schema, { storedSecrets: ['CF_DNS_API_TOKEN'] });
  expect(ui.CF_DNS_API_TOKEN).toEqual({ 'ui:widget': 'secret', 'ui:options': { stored: true } });
  expect(ui.CF_ZONE_API_TOKEN).toEqual({ 'ui:widget': 'secret', 'ui:options': { stored: false } });
  expect(ui['ui:submitButtonOptions']).toEqual({ norender: true });
});

it('hides serverPath fields the server derives itself', () => {
  const ui = buildUiSchema(route53.schema as RJSFSchema, { storedSecrets: ['secretAccessKey'] });
  expect(ui.credentialsFile).toEqual({ 'ui:widget': 'hidden' });
  expect(ui.secretAccessKey).toEqual({ 'ui:widget': 'secret', 'ui:options': { stored: true } });
});

it('humanizes a label when the schema has no title', () => {
  const s = { type: 'object', properties: { CF_API_EMAIL: { type: 'string' } } } as unknown as RJSFSchema;
  expect(buildUiSchema(s).CF_API_EMAIL).toEqual({ 'ui:title': 'CF API Email' });
});

it('fills only the listed stored secrets with the unchanged sentinel; new secrets stay absent', () => {
  expect(withSecretSentinels(schema, { CLOUDFLARE_TTL: '300' }, ['CF_DNS_API_TOKEN'])).toEqual({
    CLOUDFLARE_TTL: '300',
    CF_DNS_API_TOKEN: UNCHANGED,
  });
});

// Fix round 1 (Important #3): the authentication schema's `scopes` and
// `trustedProxies` are plain arrays of `string` with no `items.enum` —
// route them to the ListInput chip field, not RJSF's default per-item rows.
it('routes a plain array-of-string field to the ListInput field, not an array-of-enum', () => {
  const s = {
    type: 'object',
    properties: {
      trustedProxies: { type: 'array', title: 'Trusted proxies', items: { type: 'string' } },
      scopes: { type: 'array', title: 'Scopes', items: { type: 'string', enum: ['openid', 'profile'] } },
    },
  } as unknown as RJSFSchema;
  const ui = buildUiSchema(s);
  expect(ui.trustedProxies).toEqual({ 'ui:field': 'listArray' });
  // An array of `enum` items is a multi-select (ChipSet via SelectWidget),
  // not the free-text ListInput — must not also get routed here.
  expect(ui.scopes?.['ui:field']).not.toBe('listArray');
});

// Fix round 1 (Important #3): clientId's maxLength (200) sits at the
// textarea threshold (`> 200`), so it must stay a single-line input per
// Task 1C's uiSchema rule (textarea only strictly above 200).
it('keeps a maxLength-200 string field a single-line input, not a textarea', () => {
  const s = { type: 'object', properties: { clientId: { type: 'string', title: 'Client ID', maxLength: 200 } } } as unknown as RJSFSchema;
  expect(buildUiSchema(s).clientId).toBeUndefined();
});
