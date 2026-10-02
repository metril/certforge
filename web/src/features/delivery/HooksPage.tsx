import { useEffect, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { Plus } from 'lucide-react';
import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { hooksQuery, useDeleteHook } from '@/api/queries/delivery';
import type { Hook } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { PrimaryCell } from '@/components/PrimaryCell';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { PHASE_LABEL } from '@/lib/clientStatus';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import { HookSheet } from './HookSheet';
import { RowActions, UsedBy } from './RowActions';

const stickyCol = 'sticky left-0 z-10 bg-panel';

export function HooksPage() {
  const org = useOrg();
  const me = useMe();
  const canWrite = can(me, 'delivery:write', org.id);
  const { edit } = useSearch({ from: '/_app/o/$org/delivery/hooks' });
  const navigate = useNavigate({ from: '/o/$org/delivery/hooks' });
  const q = useQuery(hooksQuery(org.id));
  const del = useDeleteHook(org.id);
  const [deleting, setDeleting] = useState<Hook | null>(null);
  const openSheet = (id: string | undefined) => void navigate({ search: { edit: id }, replace: id === undefined });
  const hooks = q.data ?? [];
  // A hand-edited or stale `?edit=<id>` that no longer resolves (deleted
  // elsewhere) must not leave the page silently doing nothing — drop it
  // from the URL and say why, once the list has actually loaded.
  useEffect(() => {
    if (q.isPending || !edit || edit === 'new') return;
    if (!hooks.some((h) => h.id === edit)) {
      openSheet(undefined);
      toast.error('Hook not found.');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edit, q.isPending, hooks.map((h) => h.id).join(',')]);
  const editing = hooks.find((h) => h.id === edit);
  const add = (
    <PermissionTip allowed={canWrite} action="delivery:write">
      <Button disabled={!canWrite} onClick={() => openSheet('new')}>
        <Plus className="size-4" aria-hidden />
        New hook
      </Button>
    </PermissionTip>
  );

  return (
    <div className="grid gap-4">
      {q.isPending ? (
        <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>
      ) : q.isError ? (
        <ErrorState message={`Couldn't load hooks. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />
      ) : hooks.length === 0 ? (
        <EmptyState message="No hooks yet.">{add}</EmptyState>
      ) : (
        <>
          <div className="flex justify-end">{add}</div>
          <Table aria-label="Hooks" className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className={cn('w-56', stickyCol)}>Name</TableHead>
                <TableHead>
                  <span className="inline-flex items-center gap-1">
                    Command <HelpTip id="hook.allowlist" warning />
                  </span>
                </TableHead>
                <TableHead className="w-28">Used by</TableHead>
                <TableHead className="w-20">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {hooks.map((h) => {
                const command = h.argv.join(' ');
                return (
                  <TableRow key={h.id}>
                    <TableCell className={cn('py-1.5', stickyCol)}>
                      <PrimaryCell primary={h.name} meta={[PHASE_LABEL[h.phase], `${h.timeoutSeconds} s`]} />
                    </TableCell>
                    <TableCell className="py-1">
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span tabIndex={0} className="block truncate font-mono text-xs">
                            {command}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent side="top" className="max-w-96 break-all font-mono text-xs">
                          {command}
                        </TooltipContent>
                      </Tooltip>
                    </TableCell>
                    <TableCell className="py-1">
                      <UsedBy count={h.grantCount} />
                    </TableCell>
                    <TableCell className="py-1 text-right">
                      <RowActions name={h.name} grantCount={h.grantCount} canWrite={canWrite} onOpen={() => openSheet(h.id)} onDelete={() => setDeleting(h)} />
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </>
      )}
      {((canWrite && edit === 'new') || editing) && <HookSheet key={edit} orgId={org.id} hook={editing} readOnly={!canWrite} onOpenChange={(o) => !o && openSheet(undefined)} />}
      <ConfirmDestructive
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete hook"
        consequence="Grants can no longer pick this hook; its run history stays."
        confirmText={deleting?.name ?? ''}
        actionLabel="Delete"
        onConfirm={() => del.mutateAsync(deleting!.id)}
      />
    </div>
  );
}
