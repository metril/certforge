import type { ErrorSchema, RJSFSchema, UiSchema } from '@rjsf/utils';
import { UNCHANGED } from '@/api/types';

// Provider JSON Schemas (internal/challenge/schemas/*.json) add two
// non-standard keywords Ajv ignores (strict: false, see SchemaForm.tsx):
// `secret` marks a write-only credential field, `serverPath` marks a field
// the server derives itself and 422s if the client sends it (preflight A10).
type Prop = RJSFSchema & { secret?: boolean; serverPath?: boolean };

// An array of plain strings (no `items.enum`) maps to the ListInput chip
// widget (theme/fields.tsx's `listArray` field) instead of RJSF's default
// per-item add/remove rows.
function isPlainStringArray(p: Prop): boolean {
  const items = p.items;
  return p.type === 'array' && typeof items === 'object' && !Array.isArray(items) && items.type === 'string' && items.enum === undefined;
}

// An object field keyed by an arbitrary name (`patternProperties`/
// `additionalProperties`, no fixed `properties`) — the webhook notifier's
// `headers` (internal/notify/webhook.schema.json) — maps to the ChannelSheet's
// HeadersField (name/value rows) instead of RJSF's default per-property
// ObjectField, which has no way to add or name a property at all.
function isHeaderMap(p: Prop): boolean {
  return p.type === 'object' && !p.properties && (typeof p.patternProperties === 'object' || typeof p.additionalProperties === 'object');
}

function props(schema: RJSFSchema): [string, Prop][] {
  return Object.entries(schema.properties ?? {}).filter((e): e is [string, Prop] => typeof e[1] === 'object');
}

export function secretKeys(schema: RJSFSchema): string[] {
  return props(schema)
    .filter(([, p]) => p.secret === true)
    .map(([k]) => k);
}

/** Property keys the server derives itself; the API 422s if the client sends one (preflight A10). */
export function serverPathKeys(schema: RJSFSchema): string[] {
  return props(schema)
    .filter(([, p]) => p.serverPath === true)
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
    } else if (isPlainStringArray(p)) {
      ui[key] = { ...base, 'ui:field': 'listArray' };
    } else if (isHeaderMap(p)) {
      ui[key] = { ...base, 'ui:field': 'headers' };
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

/**
 * Maps a failed save's error message to the schema property it names (fix
 * round 1, Take now #6) — the plain settings sections (general, backup,
 * authentication) 422 with `Detail: err.Error()` from their own JSON Schema
 * checks (internal/authn/settings.go's checkAuthSettings, etc.), which name
 * their offending field by its exact JSON key (`"trustedProxies: ... is not
 * an IP address or CIDR"`, `"issuer and clientId are required..."`) but
 * don't follow the structured "Invalid <field>" title format the richer
 * issuance-defaults form parses (issuanceFields.ts's fieldFromTitle). This
 * scans the message for the first property key that appears as a whole
 * word, longest key first so one field's name can't shadow another's (e.g.
 * both `issuer` and `issuerCA` present). Returns `null` when no field name
 * appears, so the caller falls back to a toast alone — the message still
 * names the field, just not next to it.
 */
export function fieldErrorFromMessage(schema: RJSFSchema, message: string): ErrorSchema | null {
  const keys = Object.keys(schema.properties ?? {}).sort((a, b) => b.length - a.length);
  for (const key of keys) {
    // `ErrorSchema`'s mapped type (`[key in keyof T]?: ErrorSchema<T[key]>`
    // for the default `T = any`) makes TS see every string key, including
    // this literal object's own `__errors`, as needing to satisfy that
    // recursive shape too — an RJSF typing quirk unrelated to the actual
    // runtime shape (`{ [field]: { __errors: string[] } }`), which is
    // exactly what Form's own `extraErrors` prop expects.
    if (new RegExp(`\\b${key}\\b`).test(message)) return { [key]: { __errors: [message] } } as ErrorSchema;
  }
  return null;
}
