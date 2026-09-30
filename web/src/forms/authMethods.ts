import type { RJSFSchema } from '@rjsf/utils';

/** One complete way to authenticate to a DNS provider (schema-level `x-auth-methods`). */
export type AuthMethod = { id: string; label: string; fields: string[]; optional: string[] };

// Narrow view of the provider schema extensions; ProviderSchema.schema is a
// generic object in the generated API types.
type Prop = { 'x-alias-of'?: string; 'x-group'?: string; serverPath?: boolean; secret?: boolean };
type ProviderJson = { 'x-auth-methods'?: unknown; properties?: Record<string, Prop | boolean> };

function propsOf(schema: RJSFSchema): Record<string, Prop> {
  const out: Record<string, Prop> = {};
  for (const [k, v] of Object.entries((schema as ProviderJson).properties ?? {})) if (typeof v === 'object' && v) out[k] = v;
  return out;
}

export function authMethodsOf(schema: RJSFSchema): AuthMethod[] {
  const raw = (schema as ProviderJson)['x-auth-methods'];
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((m): m is Partial<AuthMethod> => typeof m === 'object' && m !== null && typeof (m as AuthMethod).id === 'string')
    .map((m) => ({ id: m.id!, label: m.label ?? m.id!, fields: m.fields ?? [], optional: m.optional ?? [] }));
}

const present = (config: Record<string, unknown>, stored: string[], k: string) =>
  stored.includes(k) || (config[k] !== undefined && config[k] !== null && config[k] !== '');

/** First fully-populated method, else the one with most fields populated, else the first. */
export function inferMethod(methods: AuthMethod[], config: Record<string, unknown>, storedSecrets: string[] = []): AuthMethod | undefined {
  const score = (m: AuthMethod) => m.fields.filter((k) => present(config, storedSecrets, k)).length;
  const complete = methods.find((m) => m.fields.length > 0 && score(m) === m.fields.length);
  if (complete) return complete;
  let best = methods[0];
  for (const m of methods) if (score(m) > score(best!)) best = m;
  return best;
}

/** Keys a method shows: its required fields then its optional ones. */
export function methodKeys(m: AuthMethod): string[] {
  return [...m.fields, ...m.optional];
}

/** Sub-schema of only the method's fields (+optional); `required` = the method's fields. Aliases and server-path fields are dropped. */
export function methodSchema(schema: RJSFSchema, method: AuthMethod): RJSFSchema {
  const all = propsOf(schema);
  const keys = methodKeys(method).filter((k) => all[k] && !all[k]!['x-alias-of'] && !all[k]!.serverPath);
  const src = (schema.properties ?? {}) as Record<string, unknown>;
  const { required: _r, additionalProperties: _a, ...rest } = schema;
  void _r;
  void _a;
  return {
    ...rest,
    properties: Object.fromEntries(keys.map((k) => [k, src[k]])) as RJSFSchema['properties'],
    required: method.fields.filter((k) => keys.includes(k)),
  };
}

/** `x-group: additional` fields that are not aliases and not used by any method. */
export function advancedSchema(schema: RJSFSchema): RJSFSchema {
  const used = new Set(authMethodsOf(schema).flatMap(methodKeys));
  const src = (schema.properties ?? {}) as Record<string, unknown>;
  const keys = Object.entries(propsOf(schema))
    .filter(([k, p]) => p['x-group'] === 'additional' && !p['x-alias-of'] && !p.serverPath && !used.has(k))
    .map(([k]) => k);
  const { required: _r, additionalProperties: _a, ...rest } = schema;
  void _r;
  void _a;
  return { ...rest, properties: Object.fromEntries(keys.map((k) => [k, src[k]])) as RJSFSchema['properties'] };
}

export function hasAdvancedValue(schema: RJSFSchema, config: Record<string, unknown>): boolean {
  return Object.keys(advancedSchema(schema).properties ?? {}).some((k) => present(config, [], k));
}
