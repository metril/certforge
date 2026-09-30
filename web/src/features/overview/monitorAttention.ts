import type { Monitor } from '@/api/types';
import { shortFp } from '@/lib/monitors';

export type MonitorAttentionKind = 'monitor-mismatch' | 'monitor-unreachable';
export type MonitorAttentionItem = { kind: MonitorAttentionKind; monitor: Monitor; cause: string };

const firstLine = (s: string) => s.split('\n')[0]!;

/** Task 8 (Deviations R12 "Overview rows"): enabled monitors currently in
 * `mismatch` or `unreachable` — the other attention kinds already exist
 * from 4B. A disabled monitor is paused, not attention-worthy. */
export function monitorAttentionItems(monitors: Monitor[]): MonitorAttentionItem[] {
  const out: MonitorAttentionItem[] = [];
  for (const m of monitors) {
    if (!m.enabled) continue;
    if (m.state === 'mismatch') {
      const fp = m.lastFingerprint ? shortFp(m.lastFingerprint) : 'an unknown certificate';
      out.push({ kind: 'monitor-mismatch', monitor: m, cause: `Serving ${fp}; expected ${m.expectedCertificateName ?? 'a CertForge certificate'}` });
    } else if (m.state === 'unreachable') {
      out.push({ kind: 'monitor-unreachable', monitor: m, cause: `Unreachable: ${firstLine(m.lastError ?? '')}` });
    }
  }
  return out;
}
