import { useQuery } from '@tanstack/react-query';
import { CircleCheck, CircleDashed, CircleX, ShieldAlert, ShieldCheck } from 'lucide-react';
import { backupStatusQuery } from '@/api/queries/backup';
import { errorMessage } from '@/api/errors';
import type { BackupStatus } from '@/api/types';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { ToneChip } from '@/components/StatusChip';
import { fmtBytes } from '@/lib/files';
import { relTime } from '@/lib/time';

function CardSkeleton() {
  return (
    <div aria-hidden className="mb-8 grid gap-3 rounded-md border border-border bg-panel p-4">
      <div className="h-4 w-40 animate-pulse rounded-sm bg-subtle" />
      <div className="h-3 w-2/3 animate-pulse rounded-sm bg-subtle" />
      <div className="h-3 w-1/2 animate-pulse rounded-sm bg-subtle" />
    </div>
  );
}

/** Which outcome to show in the "Last backup" row: the newer of a success
 * and a failure, or "never" when neither has ever happened. A scheduled or
 * on-demand run always overwrites exactly one of `lastSuccessAt`/
 * `lastFailureAt` (never both at once server-side), but either can be the
 * more recent one across several runs — e.g. a failed scheduled run after
 * an earlier successful on-demand download. */
function newerOutcome(s: BackupStatus): 'success' | 'failure' | 'never' {
  if (!s.lastSuccessAt && !s.lastFailureAt) return 'never';
  if (!s.lastFailureAt) return 'success';
  if (!s.lastSuccessAt) return 'failure';
  return Date.parse(s.lastSuccessAt) >= Date.parse(s.lastFailureAt) ? 'success' : 'failure';
}

/** Settings → Backup and keys' own status card (task-7-brief), fed by `GET
 * /backup/status`. No polling (unlike EncryptionKeyCard's rewrap progress):
 * a backup either completes inline (Back up now) or runs hourly in the
 * background, so there's nothing here that changes moment to moment. */
export function BackupStatusCard() {
  const q = useQuery(backupStatusQuery);

  if (q.isPending) return <CardSkeleton />;
  if (q.isError) {
    return <ErrorState message={`Couldn't load the backup status. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />;
  }

  const s = q.data;
  const outcome = newerOutcome(s);
  const hasArchive = s.lastSizeBytes != null && s.lastFile != null;

  return (
    <section aria-label="Backups" className="mb-8 grid gap-4 rounded-md border border-border bg-panel p-4">
      <h3 className="flex items-center gap-1.5 text-base font-semibold">
        Backups
        <HelpTip id="backup.status" />
      </h3>
      <dl className="grid gap-x-6 gap-y-3 text-sm md:grid-cols-2">
        <div className="grid gap-1">
          <dt className="text-ink-muted">Escrow</dt>
          <dd>
            {s.escrowConfirmed ? (
              <ToneChip tone="valid" icon={ShieldCheck} label="Escrow confirmed" />
            ) : (
              <ToneChip tone="expiring" icon={ShieldAlert} label="Escrow not confirmed" />
            )}
          </dd>
        </div>
        <div className="grid gap-1">
          <dt className="text-ink-muted">Last backup</dt>
          <dd className="flex flex-wrap items-center gap-2">
            {outcome === 'never' && <ToneChip tone="neutral" icon={CircleDashed} label="Never" />}
            {outcome === 'success' && (
              <>
                <ToneChip tone="valid" icon={CircleCheck} label="Succeeded" />
                <span className="text-xs text-ink-muted">{relTime(s.lastSuccessAt!)}</span>
              </>
            )}
            {outcome === 'failure' && (
              <>
                <ToneChip tone="failed" icon={CircleX} label="Failed" />
                <span className="text-xs text-ink-muted">{relTime(s.lastFailureAt!)}</span>
              </>
            )}
          </dd>
        </div>
        {hasArchive && (
          <>
            <div className="grid gap-1">
              <dt className="text-ink-muted">Size</dt>
              <dd>{fmtBytes(s.lastSizeBytes!)}</dd>
            </div>
            <div className="grid gap-1">
              <dt className="text-ink-muted">File</dt>
              <dd className="truncate font-mono text-xs">{s.lastFile}</dd>
            </div>
          </>
        )}
        <div className="grid gap-1">
          <dt className="text-ink-muted">Next</dt>
          <dd>{s.schedule === 'off' ? 'Not scheduled' : relTime(s.nextAt!)}</dd>
        </div>
        {outcome === 'failure' && s.lastError && (
          <div className="grid gap-1 md:col-span-2">
            <dt className="text-ink-muted">Error</dt>
            <dd className="text-xs text-ink-muted">{s.lastError}</dd>
          </div>
        )}
      </dl>
    </section>
  );
}
