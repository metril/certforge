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
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import { RowActions, UsedBy } from './RowActions';
import { TargetSheet } from './TargetSheet';

const stickyCol = 'sticky left-0 z-10 bg-panel';

export function TargetsPage() {
  const org = useOrg();
  const me = useMe();
  const canWrite = can(me, 'delivery:write', org.id);
  const { edit } = useSearch({ from: '/_app/o/$org/delivery/targets' });
  const navigate = useNavigate({ from: '/o/$org/delivery/targets' });
  const q = useQuery(deployTargetsQuery(org.id));
  const metaQ = useQuery(metaSchemasQuery);
  const del = useDeleteDeployTarget(org.id);
  const [deleting, setDeleting] = useState<DeployTarget | null>(null);
  const openSheet = (id: string | undefined) => void navigate({ search: (prev) => ({ ...prev, edit: id, view: undefined }), replace: id === undefined });
  // Task 8 owns the `view` param (a server target's own Grants action); Task
  // 9 renders the detail sheet it opens and its own not-found handling.
  const openView = (id: string | undefined) => void navigate({ search: (prev) => ({ ...prev, view: id, edit: undefined }) });
  const types = metaQ.data?.deployTargets ?? [];
  const typeName = (code: string) => types.find((t) => t.code === code)?.name ?? code;
  const targets = q.data ?? [];
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
  const editing = targets.find((t) => t.id === edit);
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
          <Table aria-label="Deploy targets" className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className={cn('w-44', stickyCol)}>Name</TableHead>
                <TableHead className="w-48">
                  <span className="inline-flex items-center gap-1">
                    Type <HelpTip id="target.type" />
                  </span>
                </TableHead>
                <TableHead className="w-28">
                  <span className="inline-flex items-center gap-1">
                    Runs on <HelpTip id="target.runsOn" />
                  </span>
                </TableHead>
                <TableHead className="w-56">Directory</TableHead>
                <TableHead className="w-28">
                  <span className="inline-flex items-center gap-1">
                    Used by <HelpTip id="target.usedBy" />
                  </span>
                </TableHead>
                <TableHead className="w-20">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {targets.map((t) => (
                <TableRow key={t.id} className="h-9">
                  <TableCell className={cn('truncate py-1 font-semibold', stickyCol)}>{t.name}</TableCell>
                  <TableCell className="truncate py-1">{typeName(t.type)}</TableCell>
                  <TableCell className="py-1">{t.runsOn === 'server' ? 'Server' : 'Agent'}</TableCell>
                  <TableCell title={String((t.config as { dir?: unknown }).dir ?? '')} className="truncate py-1 font-mono text-xs">
                    {String((t.config as { dir?: unknown }).dir ?? '–')}
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
        </>
      )}
      {((canWrite && edit === 'new') || editing) && types.length > 0 && (
        <TargetSheet key={edit} orgId={org.id} target={editing} types={types} readOnly={!canWrite} onOpenChange={(o) => !o && openSheet(undefined)} />
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
