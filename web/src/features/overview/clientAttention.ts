import { plural } from '@/api/queries/certificates';
import type { Client, EnrollmentRequest } from '@/api/types';
import { agentCertExpiring } from '@/lib/clientStatus';
import { relDays, relTime } from '@/lib/time';
import type { AttentionItem, AttentionKind } from './attention';
import type { MonitorAttentionItem, MonitorAttentionKind } from './monitorAttention';

export type ClientAttentionKind = 'deploy-failed' | 'drift' | 'offline' | 'agent-cert' | 'awaiting-approval';
export type ClientAttentionItem = { kind: ClientAttentionKind; client: Client; cause: string };
export type QueueItem =
  | { type: 'cert'; item: AttentionItem }
  | { type: 'client'; item: ClientAttentionItem }
  | { type: 'monitor'; item: MonitorAttentionItem };

/** design.md Dashboard: deploy failed, drift, client offline with grants,
 * agent certificate expiring. Revoked clients are out of the fleet. */
export function clientAttentionItems(clients: Client[], now = Date.now(), pending: EnrollmentRequest[] = []): ClientAttentionItem[] {
  const out: ClientAttentionItem[] = [];
  const awaiting = new Map(pending.filter((r) => Date.parse(r.expiresAt) > now).map((r) => [r.clientId, r]));
  for (const c of clients) {
    if (c.status === 'revoked') continue;
    const req = awaiting.get(c.id);
    if (req) out.push({ kind: 'awaiting-approval', client: c, cause: `Enrolment awaiting approval · expires ${relTime(req.expiresAt, now)}` });
    if (c.failedCount > 0) out.push({ kind: 'deploy-failed', client: c, cause: `${plural(c.failedCount, 'deployment')} failed` });
    if (c.driftCount > 0) out.push({ kind: 'drift', client: c, cause: `${plural(c.driftCount, 'grant')} drifted` });
    if (c.status === 'active' && !c.online && c.grantCount > 0) {
      out.push({ kind: 'offline', client: c, cause: c.lastSeen ? `Last seen ${relTime(c.lastSeen, now)}` : 'Never connected' });
    }
    if (agentCertExpiring(c, now)) out.push({ kind: 'agent-cert', client: c, cause: `Agent certificate expires ${relDays(c.agentCertNotAfter!, now)}` });
  }
  return out;
}

// One severity order for the whole queue; within a kind each input keeps
// its own order (certificates by time to impact, clients by name).
const RANK: Record<AttentionKind | ClientAttentionKind | MonitorAttentionKind, number> = {
  expired: 0,
  'awaiting-approval': 0.5,
  'manual-dns': 1,
  failed: 2,
  'monitor-mismatch': 3,
  'deploy-failed': 4,
  drift: 5,
  overdue: 6,
  'monitor-unreachable': 7,
  offline: 8,
  'agent-cert': 9,
};

export function attentionQueue(certItems: AttentionItem[], clientItems: ClientAttentionItem[], monitorItems: MonitorAttentionItem[] = []): QueueItem[] {
  const all: QueueItem[] = [
    ...certItems.map((item) => ({ type: 'cert' as const, item })),
    ...clientItems.map((item) => ({ type: 'client' as const, item })),
    ...monitorItems.map((item) => ({ type: 'monitor' as const, item })),
  ];
  return all
    .map((q, i) => ({ q, i }))
    .sort((a, b) => RANK[a.q.item.kind] - RANK[b.q.item.kind] || a.i - b.i)
    .map((x) => x.q);
}
