import type { RJSFSchema } from '@rjsf/utils';
import { UNCHANGED } from '@/api/types';
import { secretKeys } from '@/forms/uiSchema';

/** A stored secret the SchemaForm hasn't touched yet reads back as
 * `undefined`, not the `__unchanged__` sentinel — SecretInput/SchemaForm
 * fill it in on mount, but only once their own effect runs, which the
 * dirty check and the submit payload can't depend on the timing of. Both
 * normalize through this first, so a config with the sentinel already
 * applied and one that hasn't gotten there yet compare and submit
 * identically.
 *
 * This only fills a key that's missing outright (`undefined`), unlike
 * `forms/uiSchema.ts`'s `withSecretSentinels` — that one also treats a live
 * `''` as untouched, which would turn SecretInput's own Remove (which emits
 * `''` deliberately, to clear the stored secret) silently back into
 * `__unchanged__` (batch 1 review). */
export function withStoredSentinels(schema: RJSFSchema, config: Record<string, unknown>, storedSecrets: string[]): Record<string, unknown> {
  const secrets = new Set(secretKeys(schema));
  const out = { ...config };
  for (const k of storedSecrets) {
    if (secrets.has(k) && out[k] === undefined) out[k] = UNCHANGED;
  }
  return out;
}

/** The stored-secret field names for the record's own (matching) type — a
 * type switch (create only; locked on edit) carries no other type's stored
 * secrets across. */
export function storedSecretsFor(record: { type: string; storedSecrets: string[] } | undefined, type: string): string[] {
  if (!record || record.type !== type) return [];
  return record.storedSecrets;
}

/** A stable JSON snapshot of the sentinel-applied config, for dirty checks —
 * two drafts that differ only in whether the sentinel has landed yet compare
 * equal. */
export function configSnapshot(schema: RJSFSchema, config: Record<string, unknown>, storedSecrets: string[]): string {
  return JSON.stringify(withStoredSentinels(schema, config, storedSecrets));
}

type SecretProp = RJSFSchema & { secret?: boolean };

/** Strips `default` from every `secret: true` property, moving it to
 * `examples: [default]` when the property has none, so RJSF shows it only as
 * a placeholder instead of filling it into formData. Without this, RJSF
 * populates the default on edit, `withStoredSentinels` never adds the
 * sentinel (the key is no longer `undefined`), and an untouched save
 * overwrites the stored value with the schema default (preflight ruling). */
export function stripSecretDefaults(schema: RJSFSchema): RJSFSchema {
  const properties = schema.properties;
  if (!properties) return schema;
  let changed = false;
  const next: NonNullable<RJSFSchema['properties']> = { ...properties };
  for (const [key, raw] of Object.entries(properties)) {
    if (typeof raw !== 'object' || raw === null) continue;
    const p = raw as SecretProp;
    if (p.secret !== true || p.default === undefined) continue;
    changed = true;
    const { default: def, examples, ...rest } = p;
    const hasExamples = Array.isArray(examples) && examples.length > 0;
    next[key] = { ...rest, examples: hasExamples ? examples : [def] } as RJSFSchema;
  }
  return changed ? { ...schema, properties: next } : schema;
}
