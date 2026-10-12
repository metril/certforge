import { ArrowLeftRight, Cpu, Server, type LucideIcon } from 'lucide-react';
import type { RJSFSchema } from '@rjsf/utils';
import type { DeployTargetInput, Me, ProviderSchema, RunsOn } from '@/api/types';
import { help, type HelpKey } from '@/lib/help';
import { can } from '@/lib/permissions';
import { settledConfig, withStoredSentinels } from './secretForm';

/** Where a deploy target type runs (`SchemaEntry.runsOn`, 7a-facts.md). */
export type RunsOnMode = 'server' | 'agent' | 'either';
/** Whether a type ever needs the certificate's private key (`SchemaEntry.keyPolicy`). */
export type KeyPolicy = 'never' | 'optional' | 'always';

export const RUNS_ON_META: Record<RunsOnMode, { label: string; icon: LucideIcon }> = {
  server: { label: 'Server', icon: Server },
  agent: { label: 'Agent', icon: Cpu },
  either: { label: 'Server or agent', icon: ArrowLeftRight },
};

export function typeMeta(types: ProviderSchema[], code: string): ProviderSchema | undefined {
  return types.find((t) => t.code === code);
}

/** The single mode a type is locked to, or `null` for `either` (the caller
 * picks). A missing `runsOn` (no shipped type omits it, but the field is
 * optional on the wire) means `agent`, matching the server's own default. */
export function forcedRunsOn(meta: Pick<ProviderSchema, 'runsOn'> | undefined): 'server' | 'agent' | null {
  const runsOn = meta?.runsOn ?? 'agent';
  return runsOn === 'either' ? null : runsOn;
}

/** The runs-on value a new target starts with: the forced mode, or `agent`
 * for `either` (Deviations: "either default"). */
export function defaultRunsOn(meta: Pick<ProviderSchema, 'runsOn'> | undefined): 'server' | 'agent' {
  return forcedRunsOn(meta) ?? 'agent';
}

/** Mirrors the server's `needsKey` (global-constraints.md, R8): `always`
 * unconditionally, `optional` only when the draft's own `includeKey` is set,
 * `never` (or an unset policy) never. */
export function needsKey(keyPolicy: KeyPolicy | undefined, config: Record<string, unknown>): boolean {
  if (keyPolicy === 'always') return true;
  if (keyPolicy === 'optional') {
    if (config.includeKey) return true;
    const files = config.files;
    if (Array.isArray(files)) {
      const plain = ['fullchain', 'cert', 'chain'];
      return files.some((f: { content?: unknown }) => !plain.includes(String(f?.content)));
    }
  }
  return false;
}

/** True when saving as drafted would 403 — a server-run target that needs
 * the key, and the caller lacks keys:export in this org (R8). Client
 * (agent-run) targets are never gated here: the key stays with the agent's
 * own file layout, not an export. */
export function keyGateBlocks(
  me: Pick<Me, 'bindings'>,
  orgId: string,
  runsOn: RunsOnMode | RunsOn | null | undefined,
  keyPolicy: KeyPolicy | undefined,
  config: Record<string, unknown>,
): boolean {
  return runsOn === 'server' && needsKey(keyPolicy, config) && !can(me, 'keys:export', orgId);
}

function camelCase(code: string): string {
  return code.replace(/-([a-z0-9])/g, (_, c: string) => c.toUpperCase());
}

/** `target.<camelCase(code)>` when that entry exists (only `target.vaultKv`
 * today), else the generic `target.type` fallback — no per-type React code
 * (Deviations, R12). */
export function typeHelpKey(code: string): HelpKey {
  const key = `target.${camelCase(code)}`;
  return key in help ? (key as HelpKey) : 'target.type';
}

/** The target's location for the list's generic location column: the first
 * non-empty string of `url`, `dir`, `path` (task-3-brief.md), else an em dash. */
export function targetLocation(config: Record<string, unknown>): string {
  for (const key of ['url', 'dir', 'path'] as const) {
    const v = config[key];
    if (typeof v === 'string' && v !== '') return v;
  }
  return '–';
}

type TargetDraft = { name: string; type: string; runsOn: RunsOn; config: Record<string, unknown> };

/** Builds the create/update body: trims the name, applies the stored-secret
 * sentinels, and sends `runsOn` only on create — it's immutable after
 * (Shared contracts, R3), and PATCH must omit it entirely. */
export function toTargetInput(d: TargetDraft, schema: RJSFSchema, storedSecrets: string[], create: boolean): DeployTargetInput {
  const input: DeployTargetInput = {
    name: d.name.trim(),
    type: d.type as DeployTargetInput['type'],
    config: withStoredSentinels(schema, d.config, storedSecrets),
  };
  if (create) input.runsOn = d.runsOn;
  return input;
}

export type SshPreset = { id: string; label: string; config: Record<string, unknown> };

const kvmFiles = (dir: string) => [
  { path: `${dir}/server.crt`, content: 'fullchain', mode: '0644' },
  { path: `${dir}/server.key`, content: 'key', mode: '0600' },
];

/** Starting configs for the ssh target type (PiKVM and GL.iNet Comet keep a read-only root filesystem). */
export const SSH_PRESETS: SshPreset[] = [
  { id: 'kvm', label: 'PiKVM / GL.iNet Comet', config: { files: kvmFiles('/etc/kvmd/user/ssl'), preCommand: 'rw', postCommand: 'ro; systemctl restart kvmd-nginx' } },
  { id: 'kvm-legacy', label: 'PiKVM (legacy paths)', config: { files: kvmFiles('/etc/kvmd/nginx/ssl'), preCommand: 'rw', postCommand: 'ro; systemctl restart kvmd-nginx' } },
  { id: 'custom', label: 'Custom', config: {} },
];

/** The deploy credential kinds a target type accepts (its schema's credentialKinds). */
export function credentialKindsOf(schema: unknown): string[] {
  const k = (schema as { credentialKinds?: unknown } | null)?.credentialKinds;
  return Array.isArray(k) ? k.filter((x): x is string => typeof x === 'string') : [];
}

/** The schema without the fields a saved credential supplies: they are hidden
 * and no longer required. */
export function omitFields(schema: RJSFSchema, fields: string[]): RJSFSchema {
  if (fields.length === 0 || !schema.properties) return schema;
  const properties = Object.fromEntries(Object.entries(schema.properties).filter(([k]) => !fields.includes(k)));
  const required = schema.required?.filter((k) => !fields.includes(k));
  return { ...schema, properties, required };
}

// Mirrors the server's requireCredentialWrite: where a saved credential's
// secret is sent (url, host, port, RouterOS sshPort) and the pinned hostKey.
const LOCATION_KEYS = ['url', 'host', 'port', 'sshPort', 'hostKey'];

/** Whether the target's URL, host, port or pinned host key differs from the
 * saved config (defaults filled on both sides). */
export function locationChanged(schema: RJSFSchema, before: Record<string, unknown>, after: Record<string, unknown>): boolean {
  const a = settledConfig(schema, before, []);
  const b = settledConfig(schema, after, []);
  return LOCATION_KEYS.some((k) => JSON.stringify(a[k] ?? null) !== JSON.stringify(b[k] ?? null));
}
