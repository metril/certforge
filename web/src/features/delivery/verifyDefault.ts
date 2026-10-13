import type { DeployTarget } from '@/api/types';

export type VerifyDefault = { host: string; port: string };

const FROM_URL = new Set(['pfsense', 'truenas', 'routeros', 'authentik']);

/** The Verify section's starting host and port for a target; null when the target type has no endpoint to verify (hide the section). */
export function verifyDefault(target: Pick<DeployTarget, 'type' | 'config'> | undefined): VerifyDefault | null {
  if (!target || target.type === 'vault-kv') return null;
  const empty = { host: '', port: '443' };
  if (!FROM_URL.has(target.type)) return empty;
  const raw = (target.config as Record<string, unknown> | undefined)?.url;
  if (typeof raw !== 'string') return empty;
  try {
    const u = new URL(raw);
    return { host: u.hostname, port: u.port || '443' };
  } catch {
    return empty;
  }
}
