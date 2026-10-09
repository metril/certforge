import { useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleCheck, CircleDashed, CircleX, Info, X } from 'lucide-react';
import { backupStatusQuery } from '@/api/queries/backup';
import { errorMessage } from '@/api/errors';
import type { BackupStatus } from '@/api/types';
import { Card, CardBody, CardHeader } from '@/components/Card';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { IconButton } from '@/components/IconButton';
import { ToneChip } from '@/components/StatusChip';
import { help } from '@/lib/help';
import { fmtBytes } from '@/lib/files';
import { relTime } from '@/lib/time';

function CardSkeleton() {
  return (
    <div aria-hidden className="grid gap-3 rounded-md border border-border bg-panel p-4">
      <div className="h-4 w-40 animate-pulse rounded-sm bg-subtle" />
      <div className="h-3 w-2/3 animate-pulse rounded-sm bg-subtle" />
      <div className="h-3 w-1/2 animate-pulse rounded-sm bg-subtle" />
    </div>
  );
}

const REMINDER_KEY = 'cf-backup-key-reminder';

function reminderDismissed(): boolean {
  try {
    return localStorage.getItem(REMINDER_KEY) === 'dismissed';
  } catch {
    return false;
  }
}

/** The one agreed inline sentence: restoring needs the encryption key. Dismissal
 * is remembered per browser (localStorage, best effort). */
function KeyReminder() {
  const [dismissed, setDismissed] = useState(reminderDismissed);
  if (dismissed) return null;
  return (
    <div role="status" aria-label="Encryption key reminder" className="flex min-h-8 items-center gap-2 border-b border-border pb-3 text-sm text-ink-muted">
      <Info className="size-4 shrink-0" aria-hidden />
      <span>{help['backup.keyReminder'].text}</span>
      <IconButton
        type="button"
        variant="ghost"
        size="icon-xs"
        label="Dismiss"
        className="ml-auto shrink-0 rounded-sm hover:bg-subtle hover:text-ink"
        onClick={() => {
          setDismissed(true);
          try {
            localStorage.setItem(REMINDER_KEY, 'dismissed');
          } catch {
            // Storage unavailable: the reminder just returns next visit.
          }
        }}
      >
        <X className="size-4" aria-hidden />
      </IconButton>
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

/** Settings → Backups' own status card (task-7-brief), fed by `GET
 * /backup/status`. No polling (unlike EncryptionKeyCard's rewrap progress):
 * a backup either completes inline (Back up now) or runs hourly in the
 * background, so there's nothing here that changes moment to moment. */
export function BackupStatusCard({ actions }: { actions?: ReactNode }) {
  const q = useQuery(backupStatusQuery);

  if (q.isPending) return <CardSkeleton />;
  if (q.isError) {
    return <ErrorState message={`Couldn't load the backup status. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />;
  }

  const s = q.data;
  const outcome = newerOutcome(s);
  const hasArchive = s.lastSizeBytes != null && s.lastFile != null;

  return (
    <Card role="region" aria-label="Backups">
      <CardHeader
        title={
          <span className="flex items-center gap-1.5">
            Status
            <HelpTip id="backup.status" />
          </span>
        }
      />
      <CardBody className="grid gap-4">
      <KeyReminder />
      <dl className="grid gap-x-6 gap-y-3 text-sm md:grid-cols-2">
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
      {actions && <div className="flex flex-wrap items-center gap-6 border-t border-border pt-4">{actions}</div>}
      </CardBody>
    </Card>
  );
}
