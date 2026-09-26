import { Fragment, useState, type ReactNode } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { ChevronDown, Pencil, RotateCw, Trash2 } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { deployTargetsQuery, layoutsQuery } from '@/api/queries/delivery';
import { grantsQuery, useDeleteGrant, useRedeployGrant } from '@/api/queries/grants';
import type { Client, Grant } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { DeploymentChip } from '@/components/DeploymentChip';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { SwitchField } from '@/components/SwitchField';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { DELIVERY_LABEL } from '@/lib/clientStatus';
import type { HelpKey } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { relTime } from '@/lib/time';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { cn } from '@/lib/utils';
import { ClientWriteTip } from './ClientWriteTip';
import { FileCompare } from './FileCompare';

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
  const del = useDeleteGrant(orgId);
  const [removing, setRemoving] = useState<Grant | null>(null);
  const [force, setForce] = useState(false);
  const writable = canWrite && client.status !== 'revoked';
  const layoutName = (id: string | null) => (id ? (layouts.find((l) => l.id === id)?.name ?? '…') : '–');
  const targetName = (id: string | null) => (id ? (targets.find((t) => t.id === id)?.name ?? '…') : '–');
  // Only the row actually being redeployed shows as busy; other rows stay
  // clickable while one redeploy is in flight.
  const redeploying = (g: Grant) => redeploy.isPending && redeploy.variables === g.id;

  if (q.isError) return <ErrorState message={`Couldn't load grants. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />;
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
  const attention = (g: Grant) => g.deployment.state === 'drift' || g.deployment.state === 'failed';
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
          onClick={() => redeploy.mutate(g.id)}
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
      <FileCompare deployment={g.deployment} name={g.certificateName} />
      <div className="flex flex-wrap items-center gap-3 text-xs text-ink-muted">
        {g.deployment.reportedAt && <span>Reported {relTime(g.deployment.reportedAt)}</span>}
        <ClientWriteTip canWrite={canWrite} revoked={client.status === 'revoked'}>
          <Button size="sm" variant={attention(g) ? 'default' : 'outline'} disabled={!writable || redeploying(g)} onClick={() => redeploy.mutate(g.id)}>
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
                  <TableCell className="truncate py-1">{targetName(g.deployTargetId)}</TableCell>
                  <TableCell className="py-1 tabular-nums">{g.hookIds.length || '–'}</TableCell>
                  <TableCell className="py-1">{g.autoRemediate ? 'On' : 'Off'}</TableCell>
                  <TableCell className="py-1">
                    <span className="inline-flex items-center gap-1">
                      <DeploymentChip state={g.deployment.state} withHelp />
                      {toggleButton(g)}
                    </span>
                  </TableCell>
                  <TableCell className="py-1 text-right">{actions(g)}</TableCell>
                </TableRow>
                {open === g.id && (
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
                <DeploymentChip state={g.deployment.state} withHelp />
              </div>
              <span className="truncate text-xs text-ink-muted">
                {DELIVERY_LABEL[g.delivery]} · {layoutName(g.layoutId)} · {targetName(g.deployTargetId)} · {g.hookIds.length || '–'} hooks · Auto-remediate {g.autoRemediate ? 'On' : 'Off'}
              </span>
              <div className="flex items-center justify-between">
                {toggleButton(g)}
                {actions(g)}
              </div>
              {open === g.id && detail(g)}
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
