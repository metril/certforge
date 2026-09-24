import { expect, it } from 'vitest';
import type { RJSFSchema } from '@rjsf/utils';
import { UNCHANGED } from '@/api/types';
import { cloudflare, route53 } from '@/test/fixtures';
import { buildUiSchema, secretKeys, withSecretSentinels } from './uiSchema';

const schema = cloudflare.schema as RJSFSchema;

it('finds secret fields', () => {
  expect(secretKeys(schema)).toEqual(['apiToken', 'zoneToken']);
});

it('routes each secret to the secret widget with its own stored flag, and hides the submit button', () => {
  const ui = buildUiSchema(schema, { storedSecrets: ['apiToken'] });
  expect(ui.apiToken).toEqual({ 'ui:widget': 'secret', 'ui:options': { stored: true } });
  expect(ui.zoneToken).toEqual({ 'ui:widget': 'secret', 'ui:options': { stored: false } });
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
  expect(withSecretSentinels(schema, { ttl: 300 }, ['apiToken'])).toEqual({ ttl: 300, apiToken: UNCHANGED });
});
