import { useQuery } from '@tanstack/react-query';
import { Hourglass, ShieldAlert, ShieldCheck, ShieldQuestion } from 'lucide-react';
import { auditVerifyQuery } from '@/api/queries/audit';
import { ToneChip } from '@/components/StatusChip';

/** Only shown to callers with global audit:read (VerifyAuditChain needs it;
 * an org-scoped auditor gets 403 even for their own org's chain). */
export function ChainStatus() {
  const q = useQuery(auditVerifyQuery);
  if (q.isPending) return <ToneChip tone="pending" icon={Hourglass} label="Checking chain" help="audit.chain" />;
  if (q.isError) return <ToneChip tone="neutral" icon={ShieldQuestion} label="Chain status unavailable" help="audit.chain" />;
  if (!q.data.ok) return <ToneChip tone="failed" icon={ShieldAlert} label={`Chain broken at #${q.data.brokenAtId}`} help="audit.chainBroken" />;
  return <ToneChip tone="valid" icon={ShieldCheck} label="Chain verified" help="audit.chain" />;
}
