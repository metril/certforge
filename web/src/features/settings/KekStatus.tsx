import { useQuery } from '@tanstack/react-query';
import { CircleAlert, CircleCheck, CircleX } from 'lucide-react';
import { readinessQuery } from '@/api/queries/health';
import { HelpTip } from '@/components/HelpTip';
import { ToneChip } from '@/components/StatusChip';

/** Adaptation (preflight A7, controller ruling): the backup settings schema
 * dropped `kekProvider` (only `kekEscrowConfirmed` remains), so the key
 * status shown here comes from GET /readyz's `checks.kek` instead —
 * matching the same check the setup wizard gates on. */
export function KekStatus() {
  const q = useQuery(readinessQuery);
  const kek = q.data?.checks.find((c) => c.name === 'kek');

  return (
    <div className="mb-4 flex items-center gap-2">
      <span className="text-sm font-semibold">Encryption key</span>
      <HelpTip id="backup.kek" />
      {q.isPending || !kek ? (
        <span className="text-sm text-ink-muted">{q.isPending ? 'Checking…' : 'Unknown'}</span>
      ) : (
        <ToneChip
          tone={kek.ok ? 'valid' : 'failed'}
          icon={kek.ok ? CircleCheck : CircleX}
          label={kek.ok ? 'OK' : 'Failed'}
        />
      )}
      {kek?.message && <span className="text-xs text-ink-muted">{kek.message}</span>}
      {q.isError && (
        <span className="flex items-center gap-1 text-xs">
          <CircleAlert className="size-3.5 text-failed" aria-hidden />
          Could not check readiness
        </span>
      )}
    </div>
  );
}
