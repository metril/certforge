import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { Plus } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { deployTargetsQuery, useDeleteDeployTarget } from '@/api/queries/delivery';
import { metaSchemasQuery } from '@/api/queries/dns';
import { deployCredentialsQuery } from '@/api/queries/deployCredentials';
import type { DeployTarget } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HintLabel } from '@/components/HintLabel';
import { PermissionTip } from '@/components/PermissionTip';
import { PrimaryCell } from '@/components/PrimaryCell';
import { RunsOnChip } from '@/components/RunsOnChip';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { targetLocation } from '@/lib/targets';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { RowActions, UsedBy } from './RowActions';
import { failedWithoutData } from '@/lib/queryState';

export function TargetsPage() {
  const org = useOrg();
  const me = useMe();
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const canWrite = can(me, 'delivery:write', org.id);
  const navigate = useNavigate();
  const q = useQuery(deployTargetsQuery(org.id));
  const metaQ = useQuery(metaSchemasQuery);
  const del = useDeleteDeployTarget(org.id);
  const credsQ = useQuery({ ...deployCredentialsQuery(org.id), enabled: (q.data ?? []).some((t) => t.credentialId) });
  const credName = (id: string) => credsQ.data?.find((c) => c.id === id)?.name ?? 'saved credential';
  const [deleting, setDeleting] = useState<DeployTarget | null>(null);
  const go = (id: string, tab: 'overview' | 'grants' | 'edit') =>
    void navigate(tab === 'edit' ? { to: '/o/$org/delivery/targets/$id/edit', params: { org: org.slug, id } } : { to: '/o/$org/delivery/targets/$id/$tab', params: { org: org.slug, id, tab } });
  const types = metaQ.data?.deployTargets ?? [];
  const typeName = (code: string) => types.find((t) => t.code === code)?.name ?? code;
  const targets = q.data ?? [];
  // Muted second line (table row and mobile card): type, where it writes, and a note when it holds stored secrets.
  const targetMeta = (t: DeployTarget) => [
    typeName(t.type),
    targetLocation(t.config as Record<string, unknown>),
    t.credentialId ? `uses ${credName(t.credentialId)}` : t.storedSecrets.length > 0 ? 'secrets stored' : '',
  ];
  const add = metaQ.isError ? (
    <Tooltip>
      <TooltipTrigger asChild>
        <span tabIndex={0} className="inline-flex">
          <Button disabled aria-label="Add target">
            <Plus className="size-4" aria-hidden />
            Add target
          </Button>
        </span>
      </TooltipTrigger>
      <TooltipContent>Couldn't load target types.</TooltipContent>
    </Tooltip>
  ) : (
    <PermissionTip allowed={canWrite} action="delivery:write">
      <Button disabled={!canWrite || types.length === 0} onClick={() => void navigate({ to: '/o/$org/delivery/targets/new', params: { org: org.slug } })}>
        <Plus className="size-4" aria-hidden />
        Add target
      </Button>
    </PermissionTip>
  );

  return (
    <div className="grid gap-4">
      {metaQ.isError && !q.isPending && !failedWithoutData(q) && (
        <ErrorState message={`Couldn't load target types. ${errorMessage(metaQ.error)}`} onRetry={() => void metaQ.refetch()} />
      )}
      {q.isPending ? (
        <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>
      ) : failedWithoutData(q) ? (
        <ErrorState message={`Couldn't load deploy targets. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />
      ) : targets.length === 0 ? (
        <EmptyState message="No deploy targets yet.">{add}</EmptyState>
      ) : (
        <>
          <div className="flex justify-end">{add}</div>
          {isMdUp ? (
            <Table aria-label="Deploy targets" className="table-fixed">
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead className="w-32">Runs on</TableHead>
                  <TableHead className="w-28">
                    <HintLabel id="target.usedBy">Used by</HintLabel>
                  </TableHead>
                  <TableHead className="w-28">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {targets.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="py-1.5">
                      <PrimaryCell primary={t.name} link={{ to: '/o/$org/delivery/targets/$id/$tab', params: { org: org.slug, id: t.id, tab: 'overview' } }} meta={targetMeta(t)} />
                    </TableCell>
                    <TableCell className="py-1">
                      <RunsOnChip mode={t.runsOn} />
                    </TableCell>
                    <TableCell className="py-1">
                      <UsedBy count={t.grantCount} filter={{ deployTargetId: t.id }} />
                    </TableCell>
                    <TableCell className="py-1 text-right">
                      <RowActions
                        name={t.name}
                        grantCount={t.grantCount}
                        canWrite={canWrite}
                        onOpen={() => go(t.id, canWrite ? 'edit' : 'overview')}
                        onDelete={() => setDeleting(t)}
                        onGrants={t.runsOn === 'server' ? () => go(t.id, 'grants') : undefined}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <ul aria-label="Deploy targets" className="grid gap-2">
              {targets.map((t) => (
                <li key={t.id} className="grid grid-cols-1 gap-2 rounded-md border border-border bg-panel p-3">
                  <div className="flex items-center justify-between gap-2">
                    <Link to="/o/$org/delivery/targets/$id/$tab" params={{ org: org.slug, id: t.id, tab: 'overview' }} className="truncate font-semibold hover:underline">
                      {t.name}
                    </Link>
                    <RunsOnChip mode={t.runsOn} />
                  </div>
                  <span className="truncate text-xs text-ink-muted">{targetMeta(t).filter(Boolean).join(' · ')}</span>
                  <div className="flex items-center justify-between gap-2">
                    <UsedBy count={t.grantCount} filter={{ deployTargetId: t.id }} />
                    <RowActions
                      name={t.name}
                      grantCount={t.grantCount}
                      canWrite={canWrite}
                      onOpen={() => go(t.id, canWrite ? 'edit' : 'overview')}
                      onDelete={() => setDeleting(t)}
                      onGrants={t.runsOn === 'server' ? () => go(t.id, 'grants') : undefined}
                    />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      <ConfirmDestructive
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete deploy target"
        consequence="Grants can no longer pick this target."
        confirmText={deleting?.name ?? ''}
        actionLabel="Delete"
        onConfirm={() => del.mutateAsync(deleting!.id)}
      />
    </div>
  );
}
