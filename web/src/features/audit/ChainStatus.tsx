import { useQuery } from '@tanstack/react-query';
import { Hourglass, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react';
import { auditVerifyQuery } from '@/api/queries/audit';
import { ToneChip } from '@/components/StatusChip';

/** Label for a failed chain; reason is absent on a server that predates it. */
function brokenLabel(d: { brokenAtId?: number | null; reason?: string | null }): string {
  switch (d.reason) {
    case 'tail_truncated':
      return `Chain broken: newest events removed (from #${d.brokenAtId})`;
    case 'anchor_missing':
      return 'Chain broken: head anchor missing';
    case 'anchor_invalid':
      return 'Chain broken: head anchor invalid';
    case 'anchor_mismatch':
      return `Chain broken: head anchor mismatch at #${d.brokenAtId}`;
    case 'downgrade':
      return `Chain broken at #${d.brokenAtId} (legacy hash)`;
    default:
      return `Chain broken at #${d.brokenAtId}`;
  }
}

/** Only shown to callers with global audit:read (VerifyAuditChain needs it;
 * an org-scoped auditor gets 403 even for their own org's chain). */
export function ChainStatus() {
  const q = useQuery(auditVerifyQuery);
  if (q.isPending) return <ToneChip tone="pending" icon={Hourglass} label="Checking chain" help="audit.chain" />;
  if (q.isError) return <ToneChip tone="neutral" icon={ShieldQuestion} label="Chain status unavailable" help="audit.chain" />;
  if (!q.data.ok) return <ToneChip tone="failed" icon={ShieldAlert} label={brokenLabel(q.data)} help="audit.chainBroken" />;
  return <ToneChip tone="valid" icon={ShieldCheck} label="Chain verified" help="audit.chain" />;
}
