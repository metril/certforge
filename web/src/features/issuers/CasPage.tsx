import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { Lock, Pencil, Plus, Trash2 } from 'lucide-react';
import { casQuery, useDeleteCa } from '@/api/queries/cas';
import type { CA } from '@/api/types';
import { errorMessage } from '@/api/errors';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { cn } from '@/lib/utils';
import { CaSheet } from './CaSheet';

// Fix round 1 (#3/#4): first column stays put while the row scrolls
// horizontally, so a name never leaves view; matches the row's own bg so
// scrolled-under cells don't show through.
const stickyCol = 'sticky left-0 z-10 bg-panel';

export function CasPage() {
  const org = useOrg();
  const me = useMe();
  // cas:write is global-only (internal/authz/authz.go): only a global
  // binding grants it, so orgId here is purely documentation of that.
  const canWrite = can(me, 'cas:write', org.id);
  const { edit } = useSearch({ from: '/_app/o/$org/issuers/cas' });
  const navigate = useNavigate({ from: '/o/$org/issuers/cas' });
  const { data: cas = [], isPending, isError, error, refetch } = useQuery(casQuery(org.id));
  const del = useDeleteCa(org.id);
  const [deleting, setDeleting] = useState<CA | null>(null);
  // Fix round 1 (#7): closing replaces the history entry so Back doesn't
  // reopen the sheet; opening still pushes a normal entry.
  const openSheet = (id: string | undefined) => void navigate({ search: { edit: id }, replace: id === undefined });
  const editing = cas.find((c) => c.id === edit);
  const notFound = !isPending && !isError && !!edit && edit !== 'new' && !editing;

  return (
    <section className="grid gap-4" aria-label="Certificate authorities">
      {isPending ? (
        <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>
      ) : isError ? (
        <ErrorState message={`Couldn't load certificate authorities. ${errorMessage(error)}`} onRetry={() => void refetch()} />
      ) : cas.length === 0 ? (
        <EmptyState message="No certificate authorities yet.">
          <PermissionTip allowed={canWrite} action="cas:write">
            <Button disabled={!canWrite} onClick={() => openSheet('new')}>
              Add CA
            </Button>
          </PermissionTip>
        </EmptyState>
      ) : (
        <>
          <div className="flex justify-end">
            <PermissionTip allowed={canWrite} action="cas:write">
              <Button disabled={!canWrite} onClick={() => openSheet('new')}>
                <Plus className="size-4" aria-hidden />
                Add CA
              </Button>
            </PermissionTip>
          </div>
          <Table className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className={cn('w-40', stickyCol)}>Name</TableHead>
                <TableHead>
                  <span className="inline-flex items-center gap-1">
                    Directory URL <HelpTip id="ca.directoryUrl" />
                  </span>
                </TableHead>
                <TableHead className="w-24">
                  <span className="inline-flex items-center gap-1">
                    EAB <HelpTip id="ca.eab" />
                  </span>
                </TableHead>
                <TableHead className="w-20">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {cas.map((c) => (
                <TableRow key={c.id}>
                  <TableCell className={cn('truncate py-1 font-semibold', stickyCol)}>{c.name}</TableCell>
                  <TableCell className="min-w-0 truncate py-1 font-mono text-xs">{c.directoryUrl}</TableCell>
                  <TableCell className="py-1">
                    {c.hasEab ? (
                      <span className="inline-flex items-center gap-1 text-xs">
                        <Lock className="size-3.5 text-ink-muted" aria-hidden />
                        Stored
                      </span>
                    ) : (
                      '–'
                    )}
                  </TableCell>
                  <TableCell className="py-1 text-right">
                    <PermissionTip allowed={canWrite} action="cas:write" side="left">
                      <Button variant="ghost" size="icon-sm" className="size-7" disabled={!canWrite} aria-label={`Edit ${c.name}`} onClick={() => openSheet(c.id)}>
                        <Pencil className="size-3.5" aria-hidden />
                      </Button>
                    </PermissionTip>
                    <PermissionTip allowed={canWrite} action="cas:write" side="left">
                      <Button variant="ghost" size="icon-sm" className="size-7" disabled={!canWrite} aria-label={`Delete ${c.name}`} onClick={() => setDeleting(c)}>
                        <Trash2 className="size-3.5" aria-hidden />
                      </Button>
                    </PermissionTip>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </>
      )}
      {(edit === 'new' || editing) && (
        // Mount only once the CA is loaded so the form initialises from it.
        <CaSheet key={edit} orgId={org.id} open ca={editing} onOpenChange={(o) => !o && openSheet(undefined)} />
      )}
      {notFound && (
        <Sheet open onOpenChange={(o) => !o && openSheet(undefined)}>
          <SheetContent side="right" className="w-full sm:max-w-lg">
            <SheetHeader>
              <SheetTitle>CA not found</SheetTitle>
              <SheetDescription>It may have been deleted.</SheetDescription>
            </SheetHeader>
            <div className="px-4">
              <Button onClick={() => openSheet(undefined)}>Back to CAs</Button>
            </div>
          </SheetContent>
        </Sheet>
      )}
      <ConfirmDestructive
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete CA"
        consequence="Certificates and accounts that use this CA stop renewing."
        confirmText={deleting?.name ?? ''}
        actionLabel="Delete CA"
        onConfirm={() => del.mutateAsync(deleting!.id)}
      />
    </section>
  );
}
