import { forwardRef } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Check, CircleCheck, CircleX, Info, LoaderCircle, ShieldAlert, ShieldCheck, type LucideProps } from 'lucide-react';
import { toast } from 'sonner';
import { ApiError, errorMessage } from '@/api/errors';
import { keysStatusQuery, useStartRewrap } from '@/api/queries/keys';
import type { KeysStatus, RewrapTable } from '@/api/types';
import { Card } from '@/components/Card';
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
import { cn } from '@/lib/utils';

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
    <div aria-hidden className="mt-8 grid max-w-[720px] gap-3 rounded-md border border-border bg-panel p-4">
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

/** Older key configured, a re-encryption running or unfinished, or a failing
 * key check: the only times the full card (and its stepper) is worth showing. */
function needsAttention(keys: KeysStatus): boolean {
  return keys.previous.length > 0 || !keys.canaryOk || !!keys.rewrap?.running || !!keys.rewrap?.error || (keys.rewrap?.remaining ?? 0) > 0;
}

/** Which of the three rotation steps is current (0-based). */
function rotationStep(keys: KeysStatus): number {
  const older = keys.previous.length > 0;
  const r = keys.rewrap;
  const busy = !!r?.running || !!r?.error || (r?.remaining ?? 0) > 0;
  if (!older) return busy ? 1 : 0;
  // A finished run can be left over from an earlier rotation: only one for the current key counts.
  const doneForCurrentKey = !!r && r.activeKekId === keys.kekId && !busy;
  return doneForCurrentKey ? 2 : 1;
}

/** Read-only three-step progress, styled like components/Stepper (whose
 * buttons are for navigation and cannot carry a tooltip). */
function RotationSteps({ keys }: { keys: KeysStatus }) {
  const current = rotationStep(keys);
  const remaining = keys.rewrap?.remaining ?? 0;
  const steps: { label: string; extra?: React.ReactNode }[] = [
    { label: 'New key set' },
    { label: remaining > 0 ? `Re-encrypting (${remaining} left)` : 'Re-encrypting' },
    { label: 'Remove the old key', extra: <HelpTip id="keys.removeOld" /> },
  ];
  return (
    <ol className="flex flex-wrap items-center gap-x-5 gap-y-2" aria-label="Key replacement steps">
      {steps.map((st, i) => {
        const done = i < current;
        const active = i === current;
        return (
          <li key={st.label} aria-current={active ? 'step' : undefined} className={cn('flex items-center gap-2 text-sm', active ? 'font-semibold text-ink' : 'text-ink-muted')}>
            <span
              className={cn(
                'inline-flex size-6 items-center justify-center rounded-full border text-xs',
                active && 'border-primary bg-primary text-on-primary',
                done && 'border-primary text-primary',
                !active && !done && 'border-border',
              )}
            >
              {done ? <Check className="size-3.5" aria-hidden /> : i + 1}
            </span>
            {st.label}
            {st.extra}
          </li>
        );
      })}
    </ol>
  );
}

/** The everyday state: one quiet row, no controls. */
function QuietKeyRow() {
  return (
    <Card className="mt-8 flex max-w-[720px] items-center gap-3 px-4 py-3">
      <h3 className="text-sm font-semibold">Encryption key</h3>
      <ToneChip tone="valid" icon={ShieldCheck} label="Key check OK" />
      <Tooltip>
        <TooltipTrigger asChild>
          <button type="button" aria-label="Help" className="inline-flex size-4 shrink-0 items-center justify-center rounded-sm text-ink-muted hover:text-ink">
            <Info className="size-3.5" aria-hidden />
          </button>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-64 text-xs leading-snug">
          Set in the server's environment. Needed to restore any backup. To replace it, set the new key as CF_KEK, move the old one to CF_KEK_PREVIOUS, and restart.
        </TooltipContent>
      </Tooltip>
    </Card>
  );
}

/** Settings → Backups' Encryption key card, fed by `GET
 * /keys/status` (Review Focus "polling that never stops": the query polls
 * every 5s only while `rewrap.running`, and not at all otherwise —
 * keysStatusQuery's own `refetchInterval`). Shows the quiet row unless an
 * older key is configured, a re-encryption is running or unfinished, or the
 * key check fails. */
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
  if (!needsAttention(keys)) return <QuietKeyRow />;
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
    <Card role="region" aria-label="Encryption key" className="mt-8 grid max-w-[720px] gap-4 p-4">
      <h3 className="text-base font-semibold">Encryption key</h3>
      <RotationSteps keys={keys} />
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
    </Card>
  );
}
