import { ArrowLeftRight, Cpu, Server, type LucideIcon } from 'lucide-react';
import type { RJSFSchema } from '@rjsf/utils';
import type { DeployTargetInput, Me, ProviderSchema, RunsOn } from '@/api/types';
import { help, type HelpKey } from '@/lib/help';
import { can } from '@/lib/permissions';
import { withStoredSentinels } from './secretForm';

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
  if (keyPolicy === 'optional') return !!config.includeKey;
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
