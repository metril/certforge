import { Fragment, useEffect, useState } from 'react';
import { useInfiniteQuery, useQuery } from '@tanstack/react-query';
import { Link, Navigate, useNavigate } from '@tanstack/react-router';
import { ChevronLeft, KeyRound, KeySquare, Lock, Pencil, Plus, RotateCw, Trash2 } from 'lucide-react';
import { layoutsQuery, targetHookRunsInfinite } from '@/api/queries/delivery';
import { deployCredentialsQuery } from '@/api/queries/deployCredentials';
import { targetGrantsQuery, useDeleteGrant, useRedeployGrant } from '@/api/queries/grants';
import type { DeployTarget, Grant, ProviderSchema } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { RunsOnChip } from '@/components/RunsOnChip';
import { ServerDeploymentChip } from '@/components/ServerDeploymentChip';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { PageHeader } from '@/components/PageHeader';
import { TAB_ACTIVE, TAB_LINK } from '@/components/TabLabel';
import { ActionRunsList } from '@/features/clients/detail/ActionRunsTab';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { errorMessage } from '@/api/errors';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { needsKey, typeMeta } from '@/lib/targets';
import { relTime } from '@/lib/time';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { TargetForm } from './TargetForm';
import type { TargetTab } from './tabs';
import { PfSenseUsage } from './PfSenseUsage';
import { ServerGrantForm } from './ServerGrantForm';
import { failedWithoutData } from '@/lib/queryState';
import { IconButton } from '@/components/IconButton';

type Props = { orgId: string; orgSlug: string; target: DeployTarget; types: ProviderSchema[]; tab: TargetTab };

const TAB_LABEL: Record<TargetTab, string> = { overview: 'Overview', grants: 'Grants', runs: 'Action runs' };

type Mode = { kind: 'list' } | { kind: 'form'; editing?: Grant };

// Mounted only while its tab is open, so the runs are fetched (and polled) on demand.
function TargetRuns({ orgId, targetId }: { orgId: string; targetId: string }) {
  const q = useInfiniteQuery(targetHookRunsInfinite(orgId, targetId));
  return <ActionRunsList q={q} nameOf={() => 'SSH command'} empty={<EmptyState message="No action runs yet." />} />;
}

export function TargetDetail({ orgId, orgSlug, target, types, tab }: Props) {
  const me = useMe();
  const navigate = useNavigate();
  const canWrite = can(me, 'clients:write', orgId);
  const canExportKeys = can(me, 'keys:export', orgId);
  const canDelivery = can(me, 'delivery:write', orgId);
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const [mode, setMode] = useState<Mode>({ kind: 'list' });
  const [removing, setRemoving] = useState<Grant | null>(null);
  useEffect(() => setMode({ kind: 'list' }), [tab]);
  const grantsTab = target.runsOn === 'server' && tab === 'grants';
  const q = useQuery({ ...targetGrantsQuery(orgId, target.id), enabled: grantsTab });
  const layoutsQ = useQuery({ ...layoutsQuery(orgId), enabled: grantsTab });
  const layouts = layoutsQ.data ?? [];
  const credsQ = useQuery({ ...deployCredentialsQuery(orgId), enabled: !!target.credentialId });
  const credName = credsQ.data?.find((c) => c.id === target.credentialId)?.name;
  const redeploy = useRedeployGrant(orgId);
  const del = useDeleteGrant(orgId);

  const typeName = types.find((t) => t.code === target.type)?.name ?? target.type;
  const keyed = needsKey(typeMeta(types, target.type)?.keyPolicy, target.config);
  const newGrantAllowed = canWrite && (!keyed || canExportKeys);
  const newGrantReason = !canWrite ? 'clients:write' : 'keys:export';
  const layoutName = (id: string | null) => (id ? (layouts.find((l) => l.id === id)?.name ?? '…') : 'Target files');
  const redeploying = (g: Grant) => redeploy.isPending && redeploy.variables === g.id;

  const openForm = (editing?: Grant) => setMode({ kind: 'form', editing });
  const backToList = () => setMode({ kind: 'list' });

  const newGrantButton = (
    <PermissionTip allowed={newGrantAllowed} action={newGrantReason}>
      <Button type="button" size="sm" disabled={!newGrantAllowed} onClick={() => openForm()}>
        <Plus className="size-4" aria-hidden />
        New server grant
      </Button>
    </PermissionTip>
  );

  const certLink = (g: Grant) => (
    <Link to="/o/$org/certificates/$id/$tab" params={{ org: orgSlug, id: g.certificateId, tab: 'overview' }} className="truncate font-semibold hover:underline">
      {g.certificateName}
    </Link>
  );

  const actions = (g: Grant) => (
    <span className="inline-flex">
      <IconButton tip={canWrite ? undefined : `Needs the clients:write permission`}
          variant="ghost"
          size="icon-sm"
          className="size-7"
          disabled={!canWrite || redeploying(g)}
          label={`Redeploy ${g.certificateName}`}
          onClick={() => redeploy.mutate(g.id)}
        >
          <RotateCw className="size-3.5" aria-hidden />
        </IconButton>
      {/* Batch 4 review: updateServerGrant's own requireKeyIfNeeded gate
          means an includeKey target's grants need keys:export to edit at
          all, not just clients:write — same reasoning as newGrantAllowed
          above, reused here rather than only checking clients:write. */}
      <IconButton tip={newGrantAllowed ? undefined : `Needs the ${newGrantReason} permission`}
          variant="ghost"
          size="icon-sm"
          className="size-7"
          disabled={!newGrantAllowed}
          label={`Edit layout for ${g.certificateName}`}
          onClick={() => openForm(g)}
        >
          <Pencil className="size-3.5" aria-hidden />
        </IconButton>
      <IconButton tip={canWrite ? undefined : `Needs the clients:write permission`} variant="ghost" size="icon-sm" className="size-7" disabled={!canWrite} label={`Remove ${g.certificateName}`} onClick={() => setRemoving(g)}>
          <Trash2 className="size-3.5" aria-hidden />
        </IconButton>
    </span>
  );

  const statusCell = (g: Grant) => (
    <span className="inline-flex items-center gap-1.5">
      <ServerDeploymentChip status={g.serverDeployment!.status} lastError={g.serverDeployment!.lastError} withHelp />
      {g.serverDeployment!.deployedAt && <span className="text-xs text-ink-muted">{relTime(g.serverDeployment!.deployedAt)}</span>}
    </span>
  );

  const grantsList = () => {
    if (failedWithoutData(q)) return <ErrorState message={`Couldn't load grants. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />;
    if (q.isPending) return <p className="py-6 text-center text-sm text-ink-muted">Loading…</p>;
    const grants = q.data;
    if (grants.length === 0) return <EmptyState message="No certificates granted yet.">{newGrantButton}</EmptyState>;
    if (!isMdUp) {
      return (
        <ul aria-label="Grants" className="grid gap-2">
          {grants.map((g) => (
            <li key={g.id} className="grid grid-cols-1 gap-2 rounded-md border border-border bg-panel p-3">
              <div className="flex items-center justify-between gap-2">
                {certLink(g)}
                {statusCell(g)}
              </div>
              <span className="truncate text-xs text-ink-muted">{layoutName(g.layoutId)}</span>
              {target.type === 'pfsense' && <PfSenseUsage orgId={orgId} grantId={g.id} />}
              <div className="flex justify-end">{actions(g)}</div>
            </li>
          ))}
        </ul>
      );
    }
    return (
      <Table aria-label="Grants" className="table-fixed">
        <TableHeader>
          <TableRow>
            <TableHead className="w-44">Certificate</TableHead>
            <TableHead>Layout</TableHead>
            <TableHead className="w-56">Status</TableHead>
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
                <TableCell className="truncate py-1">{layoutName(g.layoutId)}</TableCell>
                <TableCell className="py-1">{statusCell(g)}</TableCell>
                <TableCell className="py-1 text-right">{actions(g)}</TableCell>
              </TableRow>
              {target.type === 'pfsense' && (
                <TableRow className="hover:bg-transparent">
                  <TableCell colSpan={4} className="whitespace-normal py-1.5">
                    <PfSenseUsage orgId={orgId} grantId={g.id} />
                  </TableCell>
                </TableRow>
              )}
            </Fragment>
          ))}
        </TableBody>
      </Table>
    );
  };

  // Grants and action runs belong to server-run targets only.
  if (tab !== 'overview' && target.runsOn !== 'server') return <Navigate to="/o/$org/delivery/targets/$id/$tab" params={{ org: orgSlug, id: target.id, tab: 'overview' }} replace />;
  const tabs = (target.runsOn === 'server' ? (['overview', 'grants', 'runs'] as const) : (['overview'] as const)).map((x) => (
    <Link key={x} to="/o/$org/delivery/targets/$id/$tab" params={{ org: orgSlug, id: target.id, tab: x }} className={TAB_LINK} activeProps={TAB_ACTIVE}>
      {TAB_LABEL[x]}
    </Link>
  ));

  return (
    <>
      <Link to="/o/$org/delivery/targets" params={{ org: orgSlug }} className="mb-2 inline-flex items-center gap-1 text-sm text-ink-muted hover:text-ink">
        <ChevronLeft className="size-4" aria-hidden />
        Deploy targets
      </Link>
      <PageHeader
        title={target.name}
        tabs={tabs}
        tabsLabel="Target sections"
        actions={
          <PermissionTip allowed={canDelivery} action="delivery:write">
            <Button type="button" variant="outline" size="sm" disabled={!canDelivery} onClick={() => void navigate({ to: '/o/$org/delivery/targets/$id/edit', params: { org: orgSlug, id: target.id } })}>
              <Pencil className="size-3.5" aria-hidden />
              Edit
            </Button>
          </PermissionTip>
        }
      >
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-ink-muted">{typeName}</span>
          <RunsOnChip mode={target.runsOn} />
            {keyed && <ToneChip tone="neutral" icon={KeyRound} label="Includes key" />}
            {target.credentialId && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Link
                    to="/o/$org/delivery/credentials"
                    params={{ org: orgSlug }}
                    search={{ edit: target.credentialId }}
                    className="inline-flex max-w-48 items-center gap-1 rounded-md border border-border px-1.5 py-0.5 text-xs hover:bg-subtle"
                  >
                    <KeySquare className="size-3.5 shrink-0" aria-hidden />
                    <span className="truncate">{credName ?? 'Saved credential'}</span>
                  </Link>
                </TooltipTrigger>
                <TooltipContent>{help['target.credential'].text}</TooltipContent>
              </Tooltip>
            )}
            {target.storedSecrets.length > 0 && (
              <Tooltip>
                <TooltipTrigger asChild>
                  <ToneChip tone="neutral" icon={Lock} label="Stored secrets" />
                </TooltipTrigger>
                <TooltipContent>{help['target.secrets'].text}</TooltipContent>
              </Tooltip>
            )}
        </div>
      </PageHeader>
      <div className="grid gap-4">
        {tab === 'overview' && <TargetForm orgId={orgId} orgSlug={orgSlug} target={target} types={types} readOnly />}
        {tab === 'grants' &&
          (mode.kind === 'form' ? (
            <ServerGrantForm orgId={orgId} orgSlug={orgSlug} targetId={target.id} editing={mode.editing} onBack={backToList} onDone={backToList} />
          ) : (
            <div className="grid gap-4">
              <div className="flex items-center justify-between gap-2">
                <h3 className="flex items-center gap-1.5 text-sm font-semibold">
                  Grants <HelpTip id="grant.server" />
                </h3>
                {(q.data?.length ?? 0) > 0 && newGrantButton}
              </div>
              {grantsList()}
            </div>
          ))}
        {tab === 'runs' && <TargetRuns orgId={orgId} targetId={target.id} />}
      </div>
      <ConfirmDestructive
        open={!!removing}
        onOpenChange={(o) => !o && setRemoving(null)}
        title="Remove grant?"
        consequence="CertForge stops pushing this certificate to the target; what is already there stays."
        confirmText={removing?.certificateName ?? ''}
        actionLabel="Remove"
        onConfirm={() => del.mutateAsync({ id: removing!.id })}
      />
    </>
  );
}
