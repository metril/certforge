import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { Plus } from 'lucide-react';
import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { deployTargetsQuery, useDeleteDeployTarget } from '@/api/queries/delivery';
import { metaSchemasQuery } from '@/api/queries/dns';
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
import { TargetDetailSheet } from './TargetDetailSheet';
import { TargetSheet } from './TargetSheet';

export function TargetsPage() {
  const org = useOrg();
  const me = useMe();
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const canWrite = can(me, 'delivery:write', org.id);
  const { edit, view } = useSearch({ from: '/_app/o/$org/delivery/targets' });
  const navigate = useNavigate({ from: '/o/$org/delivery/targets' });
  const q = useQuery(deployTargetsQuery(org.id));
  const metaQ = useQuery(metaSchemasQuery);
  const del = useDeleteDeployTarget(org.id);
  const [deleting, setDeleting] = useState<DeployTarget | null>(null);
  const openSheet = (id: string | undefined) =>
    void navigate({ search: (prev) => ({ ...prev, edit: id, view: undefined }), replace: id === undefined });
  // Task 8 owns the `view` param (a server target's own Grants action); Task
  // 9 renders the detail sheet it opens and its own not-found handling.
  const openView = (id: string | undefined) => void navigate({ search: (prev) => ({ ...prev, view: id, edit: undefined }) });
  const types = metaQ.data?.deployTargets ?? [];
  const typeName = (code: string) => types.find((t) => t.code === code)?.name ?? code;
  const targets = q.data ?? [];
  // Muted second line (table row and mobile card): type, where it writes, and a note when it holds stored secrets.
  const targetMeta = (t: DeployTarget) => [
    typeName(t.type),
    targetLocation(t.config as Record<string, unknown>),
    t.storedSecrets.length > 0 ? 'secrets stored' : '',
  ];
  // A hand-edited or stale `?edit=<id>` that no longer resolves (deleted
  // elsewhere) must not leave the page silently doing nothing — drop it
  // from the URL and say why, once the list has actually loaded.
  useEffect(() => {
    if (q.isPending || !edit || edit === 'new') return;
    if (!targets.some((t) => t.id === edit)) {
      openSheet(undefined);
      toast.error('Deploy target not found.');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edit, q.isPending, targets.map((t) => t.id).join(',')]);
  // Task 9's own detail sheet: server targets only (an agent target id, or
  // one that no longer resolves, falls through here exactly like `edit`'s
  // own not-found handling above).
  useEffect(() => {
    if (q.isPending || !view) return;
    if (!targets.some((t) => t.id === view && t.runsOn === 'server')) {
      openView(undefined);
      toast.error('Deploy target not found.');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, q.isPending, targets.map((t) => t.id).join(',')]);
  const editing = targets.find((t) => t.id === edit);
  const viewing = targets.find((t) => t.id === view && t.runsOn === 'server');
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
      <Button disabled={!canWrite || types.length === 0} onClick={() => openSheet('new')}>
        <Plus className="size-4" aria-hidden />
        Add target
      </Button>
    </PermissionTip>
  );

  return (
    <div className="grid gap-4">
      {metaQ.isError && !q.isPending && !q.isError && (
        <ErrorState message={`Couldn't load target types. ${errorMessage(metaQ.error)}`} onRetry={() => void metaQ.refetch()} />
      )}
      {q.isPending ? (
        <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>
      ) : q.isError ? (
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
                  <TableHead className="w-20">
                    <span className="sr-only">Actions</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {targets.map((t) => (
                  <TableRow key={t.id}>
                    <TableCell className="py-1.5">
                      <PrimaryCell primary={t.name} meta={targetMeta(t)} />
                    </TableCell>
                    <TableCell className="py-1">
                      <RunsOnChip mode={t.runsOn} />
                    </TableCell>
                    <TableCell className="py-1">
                      <UsedBy count={t.grantCount} />
                    </TableCell>
                    <TableCell className="py-1 text-right">
                      <RowActions
                        name={t.name}
                        grantCount={t.grantCount}
                        canWrite={canWrite}
                        onOpen={() => openSheet(t.id)}
                        onDelete={() => setDeleting(t)}
                        onGrants={t.runsOn === 'server' ? () => openView(t.id) : undefined}
                      />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <ul aria-label="Deploy targets" className="grid gap-2">
              {targets.map((t) => (
                <li key={t.id} className="grid gap-2 rounded-md border border-border bg-panel p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-semibold">{t.name}</span>
                    <RunsOnChip mode={t.runsOn} />
                  </div>
                  <span className="truncate text-xs text-ink-muted">{targetMeta(t).filter(Boolean).join(' · ')}</span>
                  <div className="flex items-center justify-between gap-2">
                    <UsedBy count={t.grantCount} />
                    <RowActions
                      name={t.name}
                      grantCount={t.grantCount}
                      canWrite={canWrite}
                      onOpen={() => openSheet(t.id)}
                      onDelete={() => setDeleting(t)}
                      onGrants={t.runsOn === 'server' ? () => openView(t.id) : undefined}
                    />
                  </div>
                </li>
              ))}
            </ul>
          )}
        </>
      )}
      {((canWrite && edit === 'new') || editing) && types.length > 0 && (
        <TargetSheet key={edit} orgId={org.id} target={editing} types={types} readOnly={!canWrite} onOpenChange={(o) => !o && openSheet(undefined)} />
      )}
      {viewing && (
        <TargetDetailSheet
          key={view}
          orgId={org.id}
          orgSlug={org.slug}
          target={viewing}
          types={types}
          onEdit={() => openSheet(viewing.id)}
          onOpenChange={(o) => !o && openView(undefined)}
        />
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
