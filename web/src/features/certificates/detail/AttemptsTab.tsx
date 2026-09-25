import { useQuery } from '@tanstack/react-query';
import { attemptsQuery } from '@/api/queries/certificates';
import { AttemptLogViewer } from '@/components/AttemptLogViewer';
import { EmptyState } from '@/components/EmptyState';
import { Button } from '@/components/ui/button';

export function AttemptsTab({ orgId, certId, onRenew }: { orgId: string; certId: string; onRenew?: () => void }) {
  const { data, isPending } = useQuery(attemptsQuery(orgId, certId));
  if (isPending) return <p className="text-ink-muted">Loading…</p>;
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
