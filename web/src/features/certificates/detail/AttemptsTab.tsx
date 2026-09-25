import { useQuery } from '@tanstack/react-query';
import { errorMessage } from '@/api/errors';
import { attemptsQuery } from '@/api/queries/certificates';
import { AttemptLogViewer } from '@/components/AttemptLogViewer';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { Button } from '@/components/ui/button';

export function AttemptsTab({ orgId, certId, onRenew }: { orgId: string; certId: string; onRenew?: () => void }) {
  const { data, isPending, isError, error, refetch } = useQuery(attemptsQuery(orgId, certId));
  if (isPending) return <p className="text-ink-muted">Loading…</p>;
  // Fix round 1 (review, Important): a failed fetch (403/500) used to fall
  // through to the empty-attempts branch below and render "No attempts yet"
  // with a Renew button — indistinguishable from a certificate that really
  // has none.
  if (isError) return <ErrorState message={`Couldn't load attempts. ${errorMessage(error)}`} onRetry={() => void refetch()} />;
  const attempts = [...(data ?? [])].sort((a, b) => Date.parse(b.startedAt) - Date.parse(a.startedAt));
  if (attempts.length === 0) {
    return (
      <EmptyState message="No attempts yet.">
        {onRenew && <Button onClick={onRenew}>Renew now</Button>}
      </EmptyState>
    );
  }
  return (
    <section aria-label="Attempts">
      {attempts.map((a, i) => (
        <AttemptLogViewer key={a.id} attempt={a} defaultOpen={i === 0} />
      ))}
    </section>
  );
}
