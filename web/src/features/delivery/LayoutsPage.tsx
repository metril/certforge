import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { Plus } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { layoutsQuery, useDeleteLayout } from '@/api/queries/delivery';
import type { Layout } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { PrimaryCell } from '@/components/PrimaryCell';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import { RowActions, UsedBy } from './RowActions';
import { failedWithoutData } from '@/lib/queryState';

const stickyCol = 'sticky left-0 z-10 bg-panel';

/** Muted second line: file names, extra certificates, and whether an export password is stored.
 * `full` swaps the names for full output paths (the tooltip's version). */
function layoutMeta(l: Layout, full = false): string[] {
  return [
    l.files.map((f) => (full ? f.path : f.path.split('/').pop())).join(', '),
    l.extraCertificateIds.length > 0 ? `+${l.extraCertificateIds.length} extra` : '',
    l.passwordSet ? 'password set' : '',
  ];
}

export function LayoutsPage() {
  const org = useOrg();
  const me = useMe();
  const canWrite = can(me, 'delivery:write', org.id);
  const navigate = useNavigate();
  const q = useQuery(layoutsQuery(org.id));
  const del = useDeleteLayout(org.id);
  const [deleting, setDeleting] = useState<Layout | null>(null);
  const layouts = q.data ?? [];
  const add = (
    <PermissionTip allowed={canWrite} action="delivery:write">
      <Button disabled={!canWrite} onClick={() => void navigate({ to: '/o/$org/delivery/layouts/new', params: { org: org.slug } })}>
        <Plus className="size-4" aria-hidden />
        New layout
      </Button>
    </PermissionTip>
  );

  return (
    <div className="grid gap-4">
      {q.isPending ? (
        <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>
      ) : failedWithoutData(q) ? (
        <ErrorState message={`Couldn't load file layouts. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />
      ) : layouts.length === 0 ? (
        <EmptyState message="No file layouts yet.">{add}</EmptyState>
      ) : (
        <>
          <div className="flex justify-end">{add}</div>
          <Table aria-label="File layouts" className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className={stickyCol}>Name</TableHead>
                <TableHead className="w-28">Used by</TableHead>
                <TableHead className="w-20">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {layouts.map((l) => (
                <TableRow key={l.id}>
                  <TableCell className={cn('py-1.5', stickyCol)}>
                    <PrimaryCell primary={l.name} meta={layoutMeta(l)} metaTitle={layoutMeta(l, true).filter(Boolean).join(' · ')} />
                  </TableCell>
                  <TableCell className="py-1">
                    <UsedBy count={l.grantCount} filter={{ layoutId: l.id }} />
                  </TableCell>
                  <TableCell className="py-1 text-right">
                    <RowActions
                      name={l.name}
                      grantCount={l.grantCount}
                      canWrite={canWrite}
                      onOpen={() => void navigate({ to: '/o/$org/delivery/layouts/$id/edit', params: { org: org.slug, id: l.id } })}
                      onDelete={() => setDeleting(l)}
                    />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </>
      )}
      <ConfirmDestructive
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete file layout"
        consequence="Grants can no longer pick this layout."
        confirmText={deleting?.name ?? ''}
        actionLabel="Delete"
        onConfirm={() => del.mutateAsync(deleting!.id)}
      />
    </div>
  );
}
