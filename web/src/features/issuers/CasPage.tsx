import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { CircleCheck, CircleX, Clock, Pencil, Plus, Trash2, type LucideIcon } from 'lucide-react';
import { casQuery, useDeleteCa } from '@/api/queries/cas';
import type { CA, CaType } from '@/api/types';
import { errorMessage } from '@/api/errors';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { PrimaryCell } from '@/components/PrimaryCell';
import { PermissionTip } from '@/components/PermissionTip';
import { FilterField } from '@/components/FilterToolbar';
import { SegmentedControl } from '@/components/SegmentedControl';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { caTone, isPrivate, KIND_LABEL, kindOf } from '@/lib/caKinds';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import type { Tone } from '@/lib/status';
import { relTime } from '@/lib/time';
import { CaDetailSheet } from './CaDetailSheet';
import { CaSheet } from './CaSheet';
import { IssuersHeader } from './IssuersLayout';
import { IconButton } from '@/components/IconButton';

const EXPIRY_ICON: Partial<Record<Tone, LucideIcon>> = { valid: CircleCheck, expiring: Clock, expired: CircleX };

function endpointOf(c: CA): string {
  if (c.type === 'localca') {
    const subject = (c.config as { subject?: { commonName?: string } } | undefined)?.subject;
    return subject?.commonName ?? '';
  }
  if (c.type === 'vaultpki') {
    const cfg = c.config as { mount?: string; role?: string } | undefined;
    return [cfg?.mount, cfg?.role].filter(Boolean).join('/');
  }
  return c.directoryUrl;
}

const FILTERS: (CaType | 'all')[] = ['all', 'acme', 'localca', 'vaultpki'];

export function CasPage() {
  const org = useOrg();
  const me = useMe();
  // cas:write is global-only (internal/authz/authz.go): only a global
  // binding grants it, so orgId here is purely documentation of that.
  const canWrite = can(me, 'cas:write', org.id);
  const { edit, view, kind, type } = useSearch({ from: '/_app/o/$org/issuers/cas' });
  const navigate = useNavigate({ from: '/o/$org/issuers/cas' });
  const { data: cas = [], isPending, isError, error, refetch } = useQuery(casQuery(org.id));
  const del = useDeleteCa(org.id);
  const [deleting, setDeleting] = useState<CA | null>(null);
  // Fix round 1 (#7): closing replaces the history entry so Back doesn't
  // reopen the sheet; opening still pushes a normal entry. Opening either
  // sheet closes the other (task-2-brief).
  const openSheet = (id: string | undefined, newKind?: CaType) =>
    void navigate({ search: (prev) => ({ ...prev, edit: id, view: undefined, kind: newKind }), replace: id === undefined });
  const openView = (id: string | undefined) =>
    void navigate({ search: (prev) => ({ ...prev, edit: undefined, view: id }), replace: id === undefined });
  const setFilter = (v: CaType | 'all') => void navigate({ search: (prev) => ({ ...prev, type: v === 'all' ? undefined : v }) });
  const editing = cas.find((c) => c.id === edit);
  // A private CA's detail sheet (task 3); an acme id in ?view= (never
  // produced by this page's own navigation) also falls through to notFound.
  const viewing = cas.find((c) => c.id === view && isPrivate(c));
  const editNotFound = !isPending && !isError && !!edit && edit !== 'new' && !editing;
  const viewNotFound = !isPending && !isError && !!view && !viewing;
  const notFound = editNotFound || viewNotFound;
  const filtered = type ? cas.filter((c) => kindOf(c) === type) : cas;

  const showList = !isPending && !isError && cas.length > 0;
  return (
    <>
      <IssuersHeader
        help="ca.type"
        actions={
          showList ? (
            <PermissionTip allowed={canWrite} action="cas:write">
              <Button disabled={!canWrite} onClick={() => openSheet('new', type)}>
                <Plus className="size-4" aria-hidden />
                Add CA
              </Button>
            </PermissionTip>
          ) : undefined
        }
        activeFilters={type ? 1 : 0}
        onClearFilters={() => setFilter('all')}
        filters={
          showList ? (
            <FilterField label="Type">
              <SegmentedControl<CaType | 'all'>
                aria-label="Type"
                value={type ?? 'all'}
                onChange={setFilter}
                options={FILTERS.map((f) => ({ value: f, label: f === 'all' ? 'All' : KIND_LABEL[f] }))}
              />
            </FilterField>
          ) : undefined
        }
      />
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
            {filtered.length === 0 ? (
              <EmptyState message={`No ${KIND_LABEL[type!]} yet.`}>
                <PermissionTip allowed={canWrite} action="cas:write">
                  <Button disabled={!canWrite} onClick={() => openSheet('new', type)}>
                    Add CA
                  </Button>
                </PermissionTip>
              </EmptyState>
            ) : (
              <Table className="table-fixed">
                <TableHeader>
                  <TableRow>
                    <TableHead>Name</TableHead>
                    <TableHead className="w-28">Expires</TableHead>
                    <TableHead className="w-20">
                      <span className="sr-only">Actions</span>
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.map((c) => {
                    const tone = c.notAfter ? caTone(c.notAfter) : 'neutral';
                    return (
                      <TableRow
                        key={c.id}
                        tabIndex={0}
                        className="cursor-pointer"
                        onClick={() => (isPrivate(c) ? openView(c.id) : openSheet(c.id))}
                        onKeyDown={(e) => {
                          // Only the row itself: Enter/Space on its Edit and Delete buttons must keep their own meaning.
                          if (e.target !== e.currentTarget || (e.key !== 'Enter' && e.key !== ' ')) return;
                          e.preventDefault();
                          if (isPrivate(c)) openView(c.id);
                          else openSheet(c.id);
                        }}
                      >
                        <TableCell className="py-1.5">
                          <PrimaryCell primary={c.name} meta={[KIND_LABEL[kindOf(c)], endpointOf(c), c.hasEab ? 'EAB stored' : '']} />
                        </TableCell>
                        <TableCell className="py-1">
                          {c.notAfter ? <ToneChip tone={tone} icon={EXPIRY_ICON[tone] ?? CircleCheck} label={relTime(c.notAfter)} /> : '–'}
                        </TableCell>
                        <TableCell className="py-1 text-right" onClick={(e) => e.stopPropagation()}>
                          <IconButton tip={canWrite ? undefined : `Needs the cas:write permission`}
                              variant="ghost"
                              size="icon-sm"
                              className="size-7"
                              disabled={!canWrite}
                              label={`Edit ${c.name}`}
                              onClick={() => openSheet(c.id)}
                            >
                              <Pencil className="size-3.5" aria-hidden />
                            </IconButton>
                          <IconButton tip={canWrite ? undefined : `Needs the cas:write permission`}
                              variant="ghost"
                              size="icon-sm"
                              className="size-7"
                              disabled={!canWrite}
                              label={`Delete ${c.name}`}
                              onClick={() => setDeleting(c)}
                            >
                              <Trash2 className="size-3.5" aria-hidden />
                            </IconButton>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            )}
          </>
        )}
        {(edit === 'new' || editing) && (
          // Mount only once the CA is loaded so the form initialises from it.
          <CaSheet key={edit} orgId={org.id} open ca={editing} initialKind={kind} onOpenChange={(o) => !o && openSheet(undefined)} />
        )}
        {viewing && (
          <CaDetailSheet
            key={view}
            orgId={org.id}
            ca={viewing}
            onEdit={() => openSheet(viewing.id)}
            onOpenChange={(o) => !o && openView(undefined)}
          />
        )}
        {notFound && (
          <Sheet open onOpenChange={(o) => !o && (editNotFound ? openSheet(undefined) : openView(undefined))}>
            <SheetContent side="right" className="w-full sm:max-w-lg">
              <SheetHeader>
                <SheetTitle>CA not found</SheetTitle>
                <SheetDescription>It may have been deleted.</SheetDescription>
              </SheetHeader>
              <div className="px-4">
                <Button onClick={() => (editNotFound ? openSheet(undefined) : openView(undefined))}>Back to CAs</Button>
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
    </>
  );
}
