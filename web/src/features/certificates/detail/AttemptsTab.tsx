import { Card } from '@/components/Card';
import { useQuery } from '@tanstack/react-query';
import { errorMessage } from '@/api/errors';
import { attemptsQuery } from '@/api/queries/certificates';
import type { AttemptStep } from '@/api/types';
import { AttemptLogViewer } from '@/components/AttemptLogViewer';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { Button } from '@/components/ui/button';
import { RateLedgerPanel } from './RateLedgerPanel';

export function AttemptsTab({ orgId, certId, caId, onRenew }: { orgId: string; certId: string; caId?: string | null; onRenew?: () => void }) {
  const { data, isPending, isError, error, refetch } = useQuery(attemptsQuery(orgId, certId));
  if (isPending) return <p className="text-ink-muted">Loading…</p>;
  // Fix round 1 (review, Important): a failed fetch (403/500) used to fall
  // through to the empty-attempts branch below and render "No attempts yet"
  // with a Renew button — indistinguishable from a certificate that really
  // has none.
  if (isError && data === undefined) return <ErrorState message={`Couldn't load attempts. ${errorMessage(error)}`} onRetry={() => void refetch()} />;
  const attempts = [...(data ?? [])].sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt));
  if (attempts.length === 0) {
    return (
      <EmptyState message="No attempts yet.">
        {onRenew && <Button onClick={onRenew}>Renew now</Button>}
      </EmptyState>
    );
  }
  const renderStepExtra = caId
    ? (step: AttemptStep) => (step.name === 'rate_ledger' && step.status === 'failed' ? <RateLedgerPanel orgId={orgId} caId={caId} certId={certId} /> : null)
    : undefined;
  return (
    <Card role="region" aria-label="Attempts" className="px-4">
      {attempts.map((a, i) => (
        <AttemptLogViewer key={a.id} orgId={orgId} certId={certId} attempt={a} defaultOpen={i === 0} renderStepExtra={renderStepExtra} />
      ))}
    </Card>
  );
}
