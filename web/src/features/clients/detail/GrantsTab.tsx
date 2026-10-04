import { Fragment, useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { ChevronDown, Pencil, RotateCw, Server, Trash2 } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { deployTargetsQuery, layoutsQuery } from '@/api/queries/delivery';
import { grantsQuery, useDeleteGrant, useRedeployGrant } from '@/api/queries/grants';
import type { Client, Grant } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { DeploymentChip } from '@/components/DeploymentChip';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { ServerDeploymentChip } from '@/components/ServerDeploymentChip';
import { ToneChip } from '@/components/StatusChip';
import { SwitchField } from '@/components/SwitchField';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { DELIVERY_LABEL } from '@/lib/clientStatus';
import type { HelpKey } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { relTime } from '@/lib/time';
import { usePendingIds } from '@/lib/usePendingIds';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { cn } from '@/lib/utils';
import { ClientWriteTip } from './ClientWriteTip';
import { FileCompare } from './FileCompare';
import { failedWithoutData } from '@/lib/queryState';

type Props = {
  client: Client;
  orgId: string;
  orgSlug: string;
  canWrite: boolean;
  open: string | undefined;
  onOpen: (grantId: string | undefined) => void;
  /** The empty state's button (Task 5: Grant certificate). */
  emptyAction?: ReactNode;
  /** Task 5: opens the grant sheet on this grant. */
  onEdit?: (g: Grant) => void;
};

function Head({ label, help, className }: { label: string; help?: HelpKey; className?: string }) {
  return (
    <TableHead className={className}>
      <span className="inline-flex items-center gap-1">
        {label}
        {help && <HelpTip id={help} />}
      </span>
    </TableHead>
  );
}

export function GrantsTab({ client, orgId, orgSlug, canWrite, open, onOpen, emptyAction, onEdit }: Props) {
  const me = useMe();
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const canDelivery = can(me, 'delivery:read', orgId);
  const q = useQuery(grantsQuery(orgId, client.id));
  const { data: layouts = [] } = useQuery({ ...layoutsQuery(orgId), enabled: canDelivery });
  const { data: targets = [] } = useQuery({ ...deployTargetsQuery(orgId), enabled: canDelivery });
  const redeploy = useRedeployGrant(orgId);
  const pendingRedeploys = usePendingIds();
  const del = useDeleteGrant(orgId);
  const [removing, setRemoving] = useState<Grant | null>(null);
  const [force, setForce] = useState(false);
  const writable = canWrite && client.status !== 'revoked';
  // Without delivery:read the lookups never run, so a named layout/target
  // can't be resolved: say so instead of showing the loading placeholder.
  const noDelivery = (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0}>—</span>
      </TooltipTrigger>
      <TooltipContent>Needs the delivery:read permission</TooltipContent>
    </Tooltip>
  );
  const layoutName = (id: string | null): ReactNode => (id ? (canDelivery ? (layouts.find((l) => l.id === id)?.name ?? '…') : noDelivery) : '–');
  const targetName = (id: string | null): ReactNode => (id ? (canDelivery ? (targets.find((t) => t.id === id)?.name ?? '…') : noDelivery) : '–');
  // Task 8: Grant.clientId/clientName/deployment are nullable for a
  // runsOn:'server' grant (5a-facts.md); this endpoint is client-scoped and
  // never actually returns one, but the table must render one safely rather
  // than dereferencing `deployment!` if it ever does.
  const targetCell = (g: Grant) =>
    g.runsOn === 'server' ? (
      <span className="inline-flex items-center gap-1">
        <ToneChip tone="neutral" icon={Server} label="Server" />
        <span className="truncate">{targetName(g.deployTargetId)}</span>
      </span>
    ) : (
      targetName(g.deployTargetId)
    );
  const stateCell = (g: Grant) =>
    g.runsOn === 'server' ? (
      <span className="inline-flex items-center gap-1.5">
        <ServerDeploymentChip status={g.serverDeployment!.status} lastError={g.serverDeployment!.lastError} withHelp />
        {g.serverDeployment!.deployedAt && <span className="text-xs text-ink-muted">{relTime(g.serverDeployment!.deployedAt)}</span>}
      </span>
    ) : (
      <span className="inline-flex items-center gap-1">
        <DeploymentChip state={g.deployment!.state} withHelp />
        {toggleButton(g)}
      </span>
    );
  // Every row with a redeploy in flight shows as busy until its own request
  // settles; other rows stay clickable.
  const redeploying = (g: Grant) => pendingRedeploys.isPending(g.id);
  const redeployRow = (g: Grant) => void pendingRedeploys.track(g.id, redeploy.mutateAsync(g.id));

  if (failedWithoutData(q)) return <ErrorState message={`Couldn't load grants. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />;
  if (q.isPending) {
    return (
      <Table aria-label="Grants" aria-busy="true" className="table-fixed">
        <TableHeader>
          <TableRow>
            <Head label="Certificate" className="w-44" />
            <Head label="Delivery" className="w-24" />
            <Head label="Layout" />
            <Head label="Target" />
            <Head label="Hooks" className="w-20" />
            <Head label="Auto-remediate" className="w-32" />
            <Head label="State" className="w-36" />
            <TableHead className="w-28">
              <span className="sr-only">Actions</span>
            </TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {Array.from({ length: 3 }).map((_, i) => (
            <TableRow key={`skeleton-${i}`} aria-hidden className="h-9 rounded-none">
              {Array.from({ length: 8 }).map((_, j) => (
                <TableCell key={j}>
                  <div className="h-3 w-3/4 animate-pulse rounded-sm bg-subtle" />
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  }
  const grants = q.data;
  if (grants.length === 0) return <EmptyState message="No certificates granted yet.">{emptyAction}</EmptyState>;

  const toggle = (g: Grant) => onOpen(open === g.id ? undefined : g.id);
  const attention = (g: Grant) => g.deployment?.state === 'drift' || g.deployment?.state === 'failed' || g.serverDeployment?.status === 'failed';
  const startRemoving = (g: Grant) => {
    setForce(false);
    setRemoving(g);
  };

  const actions = (g: Grant) => (
    <span className="inline-flex">
      {onEdit && (
        <ClientWriteTip canWrite={canWrite} revoked={client.status === 'revoked'} side="left">
          <Button variant="ghost" size="icon-sm" className="size-7" disabled={!writable} aria-label={`Edit ${g.certificateName}`} onClick={() => onEdit(g)}>
            <Pencil className="size-3.5" aria-hidden />
          </Button>
        </ClientWriteTip>
      )}
      <ClientWriteTip canWrite={canWrite} revoked={client.status === 'revoked'} side="left">
        <Button
          variant="ghost"
          size="icon-sm"
          className="size-7"
          disabled={!writable || redeploying(g)}
          aria-label={`Redeploy ${g.certificateName}`}
          onClick={() => redeployRow(g)}
        >
          <RotateCw className="size-3.5" aria-hidden />
        </Button>
      </ClientWriteTip>
      <ClientWriteTip canWrite={canWrite} revoked={client.status === 'revoked'} side="left">
        <Button variant="ghost" size="icon-sm" className="size-7" disabled={!writable} aria-label={`Remove ${g.certificateName}`} onClick={() => startRemoving(g)}>
          <Trash2 className="size-3.5" aria-hidden />
        </Button>
      </ClientWriteTip>
    </span>
  );

  const toggleButton = (g: Grant) => (
    <Button
      variant="ghost"
      size="icon-sm"
      className={cn('size-7', attention(g) && 'text-primary')}
      aria-expanded={open === g.id}
      aria-controls={`grant-${g.id}`}
      aria-label={`Files for ${g.certificateName}`}
      onClick={() => toggle(g)}
    >
      <ChevronDown className={cn('size-4 transition-transform', open === g.id && 'rotate-180')} aria-hidden />
    </Button>
  );

  const detail = (g: Grant) => (
    <section id={`grant-${g.id}`} aria-label={`Deployment of ${g.certificateName}`} className="grid gap-3 py-2">
      <FileCompare deployment={g.deployment!} name={g.certificateName} />
      <div className="flex flex-wrap items-center gap-3 text-xs text-ink-muted">
        {g.deployment?.reportedAt && <span>Reported {relTime(g.deployment.reportedAt)}</span>}
        <ClientWriteTip canWrite={canWrite} revoked={client.status === 'revoked'}>
          <Button size="sm" variant={attention(g) ? 'default' : 'outline'} disabled={!writable || redeploying(g)} onClick={() => redeployRow(g)}>
            <RotateCw className="size-3.5" aria-hidden />
            Redeploy
          </Button>
        </ClientWriteTip>
        <HelpTip id="deploy.redeploy" />
      </div>
    </section>
  );

  const certLink = (g: Grant) => (
    <Link
      to="/o/$org/certificates/$id/$tab"
      params={{ org: orgSlug, id: g.certificateId, tab: 'overview' }}
      className="truncate font-semibold hover:underline"
    >
      {g.certificateName}
    </Link>
  );

  return (
    <>
      {isMdUp ? (
        <Table aria-label="Grants" className="table-fixed">
          <TableHeader>
            <TableRow>
              <Head label="Certificate" className="w-44" />
              <Head label="Delivery" help="grant.delivery" className="w-24" />
              <Head label="Layout" help="grant.layout" />
              <Head label="Target" help="grant.target" />
              <Head label="Hooks" help="grant.hooks" className="w-20" />
              <Head label="Auto-remediate" help="grant.autoRemediate" className="w-32" />
              <Head label="State" className="w-36" />
              <TableHead className="w-28">
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {grants.map((g) => (
              <Fragment key={g.id}>
                <TableRow className="h-9">
                  <TableCell className="py-1">{certLink(g)}</TableCell>
                  <TableCell className="py-1">{DELIVERY_LABEL[g.delivery]}</TableCell>
                  <TableCell className="truncate py-1">{layoutName(g.layoutId)}</TableCell>
                  <TableCell className="truncate py-1">{targetCell(g)}</TableCell>
                  <TableCell className="py-1 tabular-nums">{g.hookIds.length || '–'}</TableCell>
                  <TableCell className="py-1">{g.autoRemediate ? 'On' : 'Off'}</TableCell>
                  <TableCell className="py-1">{stateCell(g)}</TableCell>
                  <TableCell className="py-1 text-right">{actions(g)}</TableCell>
                </TableRow>
                {open === g.id && g.deployment && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={8} className="whitespace-normal bg-subtle/40">
                      {detail(g)}
                    </TableCell>
                  </TableRow>
                )}
              </Fragment>
            ))}
          </TableBody>
        </Table>
      ) : (
        <ul aria-label="Grants" className="grid gap-2">
          {grants.map((g) => (
            <li key={g.id} className="grid gap-2 rounded-md border border-border bg-panel p-3">
              <div className="flex items-center justify-between gap-2">
                {certLink(g)}
                {g.runsOn === 'server' ? (
                  <ServerDeploymentChip status={g.serverDeployment!.status} lastError={g.serverDeployment!.lastError} withHelp />
                ) : (
                  <DeploymentChip state={g.deployment!.state} withHelp />
                )}
              </div>
              <span className="truncate text-xs text-ink-muted">
                {DELIVERY_LABEL[g.delivery]} · {layoutName(g.layoutId)} · {targetName(g.deployTargetId)} · {g.hookIds.length || '–'} hooks · Auto-remediate {g.autoRemediate ? 'On' : 'Off'}
              </span>
              <div className="flex items-center justify-between">
                {g.deployment ? toggleButton(g) : <span />}
                {actions(g)}
              </div>
              {open === g.id && g.deployment && detail(g)}
            </li>
          ))}
        </ul>
      )}
      <ConfirmDestructive
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={`Remove ${removing?.certificateName ?? ''} from ${client.name}`}
        consequence="The files are removed when the agent next syncs; until then, this grant blocks deleting the certificate, its layout, its target and its hooks."
        confirmText={removing?.certificateName ?? ''}
        actionLabel="Remove"
        onConfirm={() => del.mutateAsync({ id: removing!.id, force })}
      >
        <SwitchField
          id="grant-force-remove"
          label="Remove without waiting for the agent"
          help="grant.forceRemove"
          checked={force}
          onCheckedChange={setForce}
        />
      </ConfirmDestructive>
    </>
  );
}
