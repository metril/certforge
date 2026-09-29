import { queryOptions } from '@tanstack/react-query';
import { POLL } from '@/lib/polling';

export type Check = { name: string; ok: boolean; status: string; message?: string };
export type Readiness = { ok: boolean; checks: Check[] };

export async function fetchReadiness(): Promise<Readiness> {
  const res = await fetch(new URL('/readyz', window.location.origin), { headers: { Accept: 'application/json' } });
  let body: unknown;
  try {
    body = await res.json();
  } catch {
    body = null;
  }
  const raw = body && typeof body === 'object' ? (body as { checks?: unknown }).checks : undefined;
  const checks: Check[] =
    raw && typeof raw === 'object'
      ? Object.entries(raw as Record<string, unknown>).map(([name, v]) => {
          // 1A reports each check as a string ("ok", "failed", "unknown");
          // objects are accepted for later checks. Phase 5B Task 1: every
          // check now carries its own `status` string (Shared contracts,
          // "Readiness": /readyz's checks.vault is ok|failed|degraded), so a
          // degraded check can be told apart from an outright failure.
          if (typeof v === 'string') return { name, ok: v === 'ok', status: v, message: v === 'ok' ? undefined : v };
          const o = (v ?? {}) as { ok?: boolean; status?: string; error?: string; message?: string };
          return { name, ok: o.ok ?? o.status === 'ok', status: o.status ?? (o.ok ? 'ok' : 'failed'), message: o.error ?? o.message };
        })
      : [];
  return { ok: res.ok, checks };
}

export const readinessQuery = queryOptions({ queryKey: ['readyz'], queryFn: fetchReadiness, refetchInterval: POLL.list });
