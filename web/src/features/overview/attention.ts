import type { CertBrief } from '@/api/types';
import { DAY, HOUR, relDays } from '@/lib/time';

export type AttentionKind = 'expired' | 'manual-dns' | 'failed' | 'overdue';
export type AttentionItem = { kind: AttentionKind; cert: CertBrief; cause: string; impactAt: number };

const RANK: Record<AttentionKind, number> = { expired: 0, 'manual-dns': 1, failed: 2, overdue: 3 };

const firstLine = (s?: string | null) => (s ? s.split('\n')[0]!.slice(0, 140) : undefined);

// `impactAt` is `+Infinity` for a certificate with no current version (a
// pending manual-dns cert, most often); `Infinity - Infinity` is `NaN`,
// which makes `Array.prototype.sort`'s ordering unspecified once two such
// items land next to each other. Comparing (never subtracting) and
// tiebreaking on `cert.id` keeps the sort total and deterministic instead.
function compareNum(a: number, b: number): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/** One item per certificate that needs a look, ranked expired, manual-dns,
 * failed, overdue, then soonest impact first within a rank (ties broken by
 * certificate id, so the order is stable and testable). */
export function attentionItems(certs: CertBrief[], now = Date.now()): AttentionItem[] {
  const out: AttentionItem[] = [];
  for (const c of certs) {
    if (c.status === 'revoked') continue;
    const end = c.notAfter ? Date.parse(c.notAfter) : Number.POSITIVE_INFINITY;
    if (c.status === 'expired' || end <= now) {
      out.push({ kind: 'expired', cert: c, cause: `Expired ${c.notAfter ? relDays(c.notAfter, now) : ''}`.trim(), impactAt: end });
    } else if (c.status === 'pending' && c.manualDns) {
      out.push({ kind: 'manual-dns', cert: c, cause: 'Waiting for TXT records', impactAt: end });
    } else if (c.status === 'failed' || (c.failureCount > 0 && c.lastErrorLine)) {
      out.push({ kind: 'failed', cert: c, cause: firstLine(c.lastErrorLine) ?? 'Issuance failed', impactAt: end });
    } else if (c.status === 'active' && c.nextRenewAt && Date.parse(c.nextRenewAt) < now - HOUR) {
      out.push({ kind: 'overdue', cert: c, cause: `Renewal due ${relDays(c.nextRenewAt, now)}`, impactAt: end });
    }
  }
  return out.sort((a, b) => RANK[a.kind] - RANK[b.kind] || compareNum(a.impactAt, b.impactAt) || (a.cert.id < b.cert.id ? -1 : a.cert.id > b.cert.id ? 1 : 0));
}

export function upcomingRenewals(certs: CertBrief[], now = Date.now(), days = 7): CertBrief[] {
  return certs
    .filter((c) => c.nextRenewAt && Date.parse(c.nextRenewAt) >= now && Date.parse(c.nextRenewAt) <= now + days * DAY)
    .sort((a, b) => Date.parse(a.nextRenewAt!) - Date.parse(b.nextRenewAt!));
}
