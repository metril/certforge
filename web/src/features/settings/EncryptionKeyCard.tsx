import { forwardRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleCheck, CircleX, LoaderCircle, ShieldAlert, ShieldCheck, type LucideProps } from 'lucide-react';
import { toast } from 'sonner';
import { ApiError, errorMessage } from '@/api/errors';
import { keysStatusQuery, useStartRewrap } from '@/api/queries/keys';
import type { RewrapTable } from '@/api/types';
import { CopyField } from '@/components/CopyField';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip, HelpTipBody } from '@/components/HelpTip';
import { Meter } from '@/components/Meter';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { relTime } from '@/lib/time';

const KIND_LABEL: Record<'static' | 'vault-transit', string> = {
  static: 'Static',
  'vault-transit': 'Vault Transit',
};

// Visit order (5B/6A Shared contracts, RewrapTable enum).
const TABLE_LABEL: Record<RewrapTable, string> = {
  settings: 'Settings',
  cas: 'CAs',
  acme_accounts: 'ACME accounts',
  dns_provider_credentials: 'DNS credentials',
  output_specs: 'Output specs',
  agent_cas: 'Agent CAs',
  certificate_versions: 'Certificate versions',
  notification_channels: 'Notification channels',
  deploy_targets: 'Deploy targets',
};

const SpinIcon = forwardRef<SVGSVGElement, LucideProps>(function SpinIcon(props, ref) {
  return <LoaderCircle ref={ref} {...props} className={`${props.className ?? ''} animate-spin motion-reduce:animate-none`} />;
});

function CardSkeleton() {
  return (
    <div aria-hidden className="mb-8 grid gap-3 rounded-md border border-border bg-panel p-4">
      <div className="h-4 w-40 animate-pulse rounded-sm bg-subtle" />
      <div className="h-3 w-2/3 animate-pulse rounded-sm bg-subtle" />
      <div className="h-3 w-1/2 animate-pulse rounded-sm bg-subtle" />
    </div>
  );
}

/** Rewrap now is disabled two independent ways (task-7-brief, same
 * precedent as CaDetailSheet's RotateButton): no `settings:write`
 * (PermissionTip's own tooltip), or nothing to rewrap yet — no previous
 * KEK and no rewrap has ever run (`keys.rewrapNoPrevious`). Both never
 * need to combine in one render, so whichever applies wins outright. */
function RewrapButton({ canWrite, disabled, noPrevious, onClick }: { canWrite: boolean; disabled: boolean; noPrevious: boolean; onClick: () => void }) {
  const btn = (
    <Button type="button" disabled={!canWrite || disabled} onClick={onClick}>
      Re-encrypt now
    </Button>
  );
  if (!canWrite) return <PermissionTip allowed={false} action="settings:write">{btn}</PermissionTip>;
  if (noPrevious) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span tabIndex={0} className="inline-flex">
            {btn}
          </span>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-64 text-xs leading-snug">
          <HelpTipBody entry={help['keys.rewrapNoPrevious']} />
        </TooltipContent>
      </Tooltip>
    );
  }
  return btn;
}

/** Settings → Backups' Encryption key card, fed by `GET
 * /keys/status` (Review Focus "polling that never stops": the query polls
 * every 5s only while `rewrap.running`, and not at all otherwise —
 * keysStatusQuery's own `refetchInterval`). Replaces `KekStatus` (which
 * read `/readyz`'s `checks.kek`; 5B plan Deviations R7). */
export function EncryptionKeyCard() {
  const me = useMe();
  const canWrite = can(me, 'settings:write');
  const q = useQuery(keysStatusQuery);
  const startRewrap = useStartRewrap();

  if (q.isPending) return <CardSkeleton />;
  if (q.isError) {
    return <ErrorState message={`Couldn't load the encryption key. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />;
  }

  const keys = q.data;
  const rewrap = keys.rewrap;
  const noPrevious = keys.previous.length === 0 && rewrap === null;

  async function handleRewrap() {
    try {
      await startRewrap.mutateAsync();
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        toast.error('Re-encryption is already running');
        void q.refetch();
        return;
      }
      toast.error(errorMessage(e));
    }
  }

  return (
    <section aria-label="Encryption key" className="mb-8 grid gap-4 rounded-md border border-border bg-panel p-4">
      <h3 className="text-base font-semibold">Encryption key</h3>
      <dl className="grid gap-x-6 gap-y-3 text-sm md:grid-cols-2">
        <div className="grid gap-1">
          <dt className="flex items-center gap-1 text-ink-muted">
            Kind
            <HelpTip id="keys.kind" />
          </dt>
          <dd className="flex flex-wrap items-center gap-2">
            {KIND_LABEL[keys.kind]}
            {keys.kind === 'vault-transit' && keys.vaultAddress && <span className="font-mono text-xs text-ink-muted">{keys.vaultAddress}</span>}
          </dd>
        </div>
        <div className="grid gap-1">
          <dt className="text-ink-muted">Key ID</dt>
          <dd>
            <CopyField value={keys.kekId} label="key ID" display={keys.kekId.length > 24 ? `${keys.kekId.slice(0, 24)}…` : keys.kekId} />
          </dd>
        </div>
        <div className="grid gap-1">
          <dt className="flex items-center gap-1 text-ink-muted">
            Key check
            <HelpTip id="keys.canary" />
          </dt>
          <dd>
            {keys.canaryOk ? (
              <ToneChip tone="valid" icon={ShieldCheck} label="Key check OK" />
            ) : (
              <ToneChip tone="failed" icon={ShieldAlert} label="Key check failed" />
            )}
          </dd>
        </div>
        <div className="grid gap-1">
          <dt className="flex items-center gap-1 text-ink-muted">
            Older keys
            <HelpTip id="keys.previous" />
          </dt>
          <dd>
            {keys.previous.length === 0 ? (
              <span className="text-ink-muted">None</span>
            ) : (
              <ul className="flex flex-wrap gap-1.5">
                {keys.previous.map((p) => (
                  <li
                    key={p.kekId}
                    title={`${p.kind} · ${p.kekId}`}
                    className="inline-flex h-6 max-w-56 items-center truncate rounded-sm border border-border bg-subtle px-2 font-mono text-xs"
                  >
                    {p.kind} · {p.kekId}
                  </li>
                ))}
              </ul>
            )}
          </dd>
        </div>
      </dl>

      {rewrap && (
        <div className="grid gap-3 border-t border-border pt-3">
          <div className="flex flex-wrap items-center gap-2">
            {rewrap.running ? (
              <ToneChip tone="pending" icon={SpinIcon} label="Running" />
            ) : rewrap.error ? (
              <ToneChip tone="failed" icon={CircleX} label="Failed" />
            ) : (
              <ToneChip tone="valid" icon={CircleCheck} label="Finished" />
            )}
            {rewrap.error && <span className="text-xs text-failed">{rewrap.error}</span>}
          </div>
          <p className="text-xs text-ink-muted">
            Started {relTime(rewrap.startedAt)}
            {rewrap.finishedAt && <> · Finished {relTime(rewrap.finishedAt)}</>}
            {' · '}
            <span className="font-mono">Remaining {rewrap.remaining}</span>
          </p>
          <ul className="grid gap-2">
            {rewrap.tables.map((t) => (
              <li key={t.table} className="flex flex-wrap items-center gap-x-3 gap-y-1 md:flex-nowrap">
                <span className="w-40 shrink-0">{TABLE_LABEL[t.table]}</span>
                <Meter value={t.scanned} max={t.scanned + t.remaining} label={`${TABLE_LABEL[t.table]} re-encryption progress`} />
                <span className="font-mono text-xs">
                  {t.rewrapped} / {t.scanned}
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="flex items-center gap-2">
        <RewrapButton
          canWrite={canWrite}
          disabled={!!rewrap?.running || startRewrap.isPending || noPrevious}
          noPrevious={noPrevious}
          onClick={() => void handleRewrap()}
        />
        <HelpTip id="keys.rewrap" />
      </div>
    </section>
  );
}
