import type { Certificate, EffectiveMap, VerificationRule } from '@/api/types';
import { DAY, HOUR, relDays } from '@/lib/time';

export type AttentionKind = 'expired' | 'manual-dns' | 'failed' | 'overdue';
export type AttentionItem = { kind: AttentionKind; cert: Certificate; cause: string; impactAt: number };

const RANK: Record<AttentionKind, number> = { expired: 0, 'manual-dns': 1, failed: 2, overdue: 3 };

/** A certificate is waiting on manual DNS if any of its own rules (or, once
 * it has none of its own, the inherited catch-all rules) use manual-dns. */
export function usesManualDns(c: Certificate): boolean {
  const eff = ((c.effective as EffectiveMap | undefined)?.verificationRules?.value ?? []) as VerificationRule[];
  return (c.verificationRules.length ? c.verificationRules : eff).some((r) => r.method === 'manual-dns');
}

const firstLine = (s?: string | null) => (s ? s.split('\n')[0]!.slice(0, 140) : undefined);

/** One item per certificate that needs a look, ranked expired, manual-dns,
 * failed, overdue, then soonest impact first within a rank. */
export function attentionItems(certs: Certificate[], now = Date.now()): AttentionItem[] {
  const out: AttentionItem[] = [];
  for (const c of certs) {
    if (c.status === 'revoked') continue;
    const end = c.currentVersion ? Date.parse(c.currentVersion.notAfter) : Number.POSITIVE_INFINITY;
    if (c.status === 'expired' || end <= now) {
      out.push({ kind: 'expired', cert: c, cause: `Expired ${c.currentVersion ? relDays(c.currentVersion.notAfter, now) : ''}`.trim(), impactAt: end });
    } else if (c.status === 'pending' && usesManualDns(c)) {
      out.push({ kind: 'manual-dns', cert: c, cause: 'Waiting for TXT records', impactAt: end });
    } else if (c.status === 'failed' || (c.failureCount > 0 && c.lastError)) {
      out.push({ kind: 'failed', cert: c, cause: firstLine(c.lastError) ?? 'Issuance failed', impactAt: end });
    } else if (c.status === 'active' && c.nextRenewAt && Date.parse(c.nextRenewAt) < now - HOUR) {
      out.push({ kind: 'overdue', cert: c, cause: `Renewal due ${relDays(c.nextRenewAt, now)}`, impactAt: end });
    }
  }
  return out.sort((a, b) => RANK[a.kind] - RANK[b.kind] || a.impactAt - b.impactAt);
}

export function statusCounts(certs: Certificate[]) {
  const counts = { active: 0, pending: 0, failed: 0, expired: 0 };
  for (const c of certs) if (c.status in counts) counts[c.status as keyof typeof counts]++;
  return counts;
}

export function upcomingRenewals(certs: Certificate[], now = Date.now(), days = 7): Certificate[] {
  return certs
    .filter((c) => c.nextRenewAt && Date.parse(c.nextRenewAt) >= now && Date.parse(c.nextRenewAt) <= now + days * DAY)
    .sort((a, b) => Date.parse(a.nextRenewAt!) - Date.parse(b.nextRenewAt!));
}
