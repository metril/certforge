import type { RJSFSchema, UiSchema } from '@rjsf/utils';
import { UNCHANGED } from '@/api/types';

// Provider JSON Schemas (internal/challenge/schemas/*.json) add two
// non-standard keywords Ajv ignores (strict: false, see SchemaForm.tsx):
// `secret` marks a write-only credential field, `serverPath` marks a field
// the server derives itself and 422s if the client sends it (preflight A10).
type Prop = RJSFSchema & { secret?: boolean; serverPath?: boolean };

function props(schema: RJSFSchema): [string, Prop][] {
  return Object.entries(schema.properties ?? {}).filter((e): e is [string, Prop] => typeof e[1] === 'object');
}

export function secretKeys(schema: RJSFSchema): string[] {
  return props(schema)
    .filter(([, p]) => p.secret === true)
    .map(([k]) => k);
}

// snake_case / SCREAMING_SNAKE_CASE / camelCase -> "Title Case", keeping
// short (<=3 char) runs upper-cased so acronyms (API, ID, URL, TTL, ...)
// read naturally. Only used as a fallback when the schema has no title.
function humanize(key: string): string {
  const spaced = key
    .replace(/([a-z0-9])([A-Z])/g, '$1 $2')
    .replace(/[_-]+/g, ' ')
    .trim();
  return spaced
    .split(/\s+/)
    .filter(Boolean)
    .map((w) => (w.length <= 3 ? w.toUpperCase() : w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()))
    .join(' ');
}

/**
 * Builds the uiSchema for a provider config form: routes `secret: true`
 * fields to the secret widget with their own stored flag (controller
 * ruling: no global "has secrets" boolean — `storedSecrets` names the
 * fields that already have a value, mirroring `DNSCredential.storedSecrets`),
 * hides `serverPath` fields the API derives itself (and 422s if sent), and
 * falls back to a humanized label / an example placeholder when the schema
 * doesn't supply a title / examples.
 */
export function buildUiSchema(schema: RJSFSchema, opts: { storedSecrets?: string[] } = {}): UiSchema {
  const stored = new Set(opts.storedSecrets ?? []);
  const ui: UiSchema = { 'ui:submitButtonOptions': { norender: true } };
  for (const [key, p] of props(schema)) {
    if (p.serverPath === true) {
      ui[key] = { 'ui:widget': 'hidden' };
      continue;
    }
    const base: Record<string, unknown> = {};
    if (typeof p.title !== 'string' || p.title === '') base['ui:title'] = humanize(key);
    const example = Array.isArray(p.examples) && typeof p.examples[0] === 'string' ? p.examples[0] : undefined;
    if (example) base['ui:placeholder'] = example;

    if (p.secret === true) {
      ui[key] = { ...base, 'ui:widget': 'secret', 'ui:options': { stored: stored.has(key) } };
    } else if (p.type === 'string' && (p.format === 'textarea' || (p.maxLength ?? 0) > 200)) {
      ui[key] = { ...base, 'ui:widget': 'textarea' };
    } else if (Object.keys(base).length > 0) {
      ui[key] = base;
    }
  }
  return ui;
}

/**
 * Seeds untouched stored secrets with the unchanged sentinel so a caller
 * that starts formData from the credential's own config never drops one on
 * submit. Secrets not listed in `storedSecrets` are new and stay write-only
 * (left absent until the caller types a value).
 */
export function withSecretSentinels(schema: RJSFSchema, value: Record<string, unknown>, storedSecrets: string[] = []): Record<string, unknown> {
  const secrets = new Set(secretKeys(schema));
  const out = { ...value };
  for (const k of storedSecrets) {
    if (secrets.has(k) && (out[k] === undefined || out[k] === null || out[k] === '')) out[k] = UNCHANGED;
  }
  return out;
}
