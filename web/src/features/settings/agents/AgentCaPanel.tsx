import { Card, CardBody, CardHeader } from '@/components/Card';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Ban, Clock, RefreshCw, ShieldCheck, type LucideIcon } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { agentCAsQuery, useRetireAgentCA, useRotateAgentCA } from '@/api/queries/agents';
import { plural } from '@/api/queries/certificates';
import type { AgentCA } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { CopyField } from '@/components/CopyField';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { shortHash } from '@/lib/clientStatus';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { EXPIRING_DAYS, type Tone } from '@/lib/status';
import { daysUntil, fmtDate, relDays } from '@/lib/time';
import { failedWithoutData } from '@/lib/queryState';

const STATUS: Record<AgentCA['status'], { label: string; tone: Tone; icon: LucideIcon }> = {
  active: { label: 'Active', tone: 'valid', icon: ShieldCheck },
  retiring: { label: 'Retiring', tone: 'expiring', icon: Clock },
  retired: { label: 'Retired', tone: 'neutral', icon: Ban },
};

export function AgentCaPanel() {
  const me = useMe();
  const canWrite = can(me, 'settings:write');
  const q = useQuery(agentCAsQuery);
  const rotate = useRotateAgentCA();
  const retire = useRetireAgentCA();
  // Fix round 1 (review, minor #4): two separate pieces of state instead of
  // a `{kind, ca}` union whose `onConfirm` needed a `''` fallback id for the
  // cases (rotate, closed) where there was no CA to retire. `retireTarget`
  // itself is the one source of truth for which CA (if any) Retire targets,
  // so `ConfirmDestructive`'s `onConfirm` always has a real id.
  const [rotateOpen, setRotateOpen] = useState(false);
  const [retireTarget, setRetireTarget] = useState<AgentCA | null>(null);

  if (q.isPending) return <p className="text-ink-muted">Loading…</p>;
  if (failedWithoutData(q)) return <ErrorState message={`Couldn't load agent CAs. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />;
  const { items, listener } = q.data;
  const issuer = items.find((c) => c.id === listener.caId);
  const expiring = listener.notAfter !== null && daysUntil(listener.notAfter) < EXPIRING_DAYS;

  return (
    <>
      <Card role="region" aria-label="Listener certificate" className="max-w-[720px]">
        <CardHeader
          title={
            <span className="flex items-center gap-1.5">
              Listener certificate <HelpTip id="agents.listener" />
            </span>
          }
        />
        <CardBody>
        {listener.notAfter ? (
          <dl className="grid grid-cols-1 gap-x-4 gap-y-2 text-sm sm:grid-cols-[120px_minmax(0,1fr)] sm:items-center">
            <dt className="text-ink-muted">Names</dt>
            <dd>
              <ul aria-label="Listener names" className="flex flex-wrap gap-1.5">
                {listener.names.map((n) => (
                  <li key={n} className="inline-flex h-6 items-center rounded-sm border border-border bg-subtle px-2 font-mono text-xs">
                    {n}
                  </li>
                ))}
              </ul>
            </dd>
            <dt className="text-ink-muted">Expires</dt>
            <dd>{expiring ? <ToneChip tone="expiring" icon={Clock} label={`Expires ${relDays(listener.notAfter)}`} /> : `Expires ${relDays(listener.notAfter)}`}</dd>
            <dt className="text-ink-muted">Issued by</dt>
            <dd className="font-mono text-xs">{shortHash(issuer?.fingerprint ?? null)}</dd>
          </dl>
        ) : (
          <p className="flex items-center gap-1.5 text-sm text-ink-muted">
            The agent listener is not running.
            <HelpTip id="agents.listenerNotRunning" />
          </p>
        )}
        </CardBody>
      </Card>
      <Card role="region" aria-label="Agent certificate authorities">
        <CardHeader
          title={
            <span className="flex items-center gap-1.5">
              Agent CAs <HelpTip id="agents.ca" />
            </span>
          }
          actions={
          <PermissionTip allowed={canWrite} action="settings:write">
            <Button variant="outline" disabled={!canWrite || rotate.isPending} onClick={() => setRotateOpen(true)}>
              <RefreshCw className="size-4" aria-hidden />
              Rotate
            </Button>
          </PermissionTip>
          }
        />
        <CardBody>
        <ul aria-label="Agent CAs" className="grid">
          {items.map((ca) => {
            const s = STATUS[ca.status];
            const inUse = ca.activeClientCerts > 0;
            const retireButton = (
              <Button size="sm" variant="outline" disabled={!canWrite || inUse} onClick={() => setRetireTarget(ca)}>
                Retire
              </Button>
            );
            return (
              <li
                key={ca.id}
                className="grid gap-2 border-b border-border py-2 text-sm last:border-0 md:min-h-9 md:grid-cols-[112px_minmax(0,1fr)_160px_96px_88px] md:items-center md:gap-3 md:py-1"
              >
                <ToneChip tone={s.tone} icon={s.icon} label={s.label} />
                <CopyField value={ca.fingerprint} display={`${ca.fingerprint.slice(0, 16)}…`} label="CA fingerprint" />
                <span className="text-ink-muted">Valid until {fmtDate(ca.notAfter)}</span>
                <span className="inline-flex items-center gap-1 tabular-nums">
                  {plural(ca.activeClientCerts, 'agent')}
                  <HelpTip id="agents.activeCerts" />
                </span>
                <span className="md:text-right">
                  {ca.status === 'retiring' &&
                    (!canWrite ? (
                      <PermissionTip allowed={false} action="settings:write" side="left">
                        {retireButton}
                      </PermissionTip>
                    ) : inUse ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span tabIndex={0} className="inline-flex">
                            {retireButton}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent side="left">{`${plural(ca.activeClientCerts, 'agent')} still use it. They move to the new CA as they renew.`}</TooltipContent>
                      </Tooltip>
                    ) : (
                      retireButton
                    ))}
                </span>
              </li>
            );
          })}
        </ul>
        </CardBody>
      </Card>
      <ConfirmDestructive
        open={rotateOpen}
        onOpenChange={setRotateOpen}
        title="Rotate agent CA"
        consequence="Agents move to the new CA as they renew; unused enrolment tokens keep working until the old CA is retired."
        help="agents.rotate"
        confirmText="rotate"
        actionLabel="Rotate"
        onConfirm={() => rotate.mutateAsync()}
      />
      <ConfirmDestructive
        open={retireTarget !== null}
        onOpenChange={(o) => !o && setRetireTarget(null)}
        title="Retire agent CA"
        consequence="The listener certificate switches to the next CA, and agents enrolling with tokens pinned to this one will refuse to connect."
        help="agents.retire"
        confirmText="retire"
        actionLabel="Retire"
        onConfirm={() => retire.mutateAsync(retireTarget!.id)}
      />
    </>
  );
}
