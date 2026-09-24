import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { Lock, Pencil, Plus, Trash2 } from 'lucide-react';
import { casQuery, useDeleteCa } from '@/api/queries/cas';
import type { CA } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { useOrg } from '@/lib/org';
import { CaSheet } from './CaSheet';

export function CasPage() {
  const org = useOrg();
  const { edit } = useSearch({ from: '/_app/o/$org/issuers/cas' });
  const navigate = useNavigate({ from: '/o/$org/issuers/cas' });
  const { data: cas = [], isPending } = useQuery(casQuery(org.id));
  const del = useDeleteCa(org.id);
  const [deleting, setDeleting] = useState<CA | null>(null);
  const openSheet = (id: string | undefined) => void navigate({ search: { edit: id } });
  const editing = cas.find((c) => c.id === edit);

  return (
    <section className="grid gap-4" aria-label="Certificate authorities">
      {isPending ? null : cas.length === 0 ? (
        <EmptyState message="No certificate authorities yet.">
          <Button onClick={() => openSheet('new')}>Add CA</Button>
        </EmptyState>
      ) : (
        <>
          <div className="flex justify-end">
            <Button onClick={() => openSheet('new')}>
              <Plus className="size-4" aria-hidden />
              Add CA
            </Button>
          </div>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>
                  <span className="inline-flex items-center gap-1">
                    Directory URL <HelpTip id="ca.directoryUrl" />
                  </span>
                </TableHead>
                <TableHead>
                  <span className="inline-flex items-center gap-1">
                    EAB <HelpTip id="ca.eab" />
                  </span>
                </TableHead>
                <TableHead className="w-24">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {cas.map((c) => (
                <TableRow key={c.id} className="h-9">
                  <TableCell className="font-semibold">{c.name}</TableCell>
                  <TableCell className="max-w-96 truncate font-mono text-xs">{c.directoryUrl}</TableCell>
                  <TableCell>
                    {c.hasEab ? (
                      <span className="inline-flex items-center gap-1 text-xs">
                        <Lock className="size-3.5 text-ink-muted" aria-hidden />
                        Stored
                      </span>
                    ) : (
                      '–'
                    )}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button variant="ghost" size="icon" aria-label={`Edit ${c.name}`} onClick={() => openSheet(c.id)}>
                      <Pencil className="size-4" aria-hidden />
                    </Button>
                    <Button variant="ghost" size="icon" aria-label={`Delete ${c.name}`} onClick={() => setDeleting(c)}>
                      <Trash2 className="size-4" aria-hidden />
                    </Button>
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
