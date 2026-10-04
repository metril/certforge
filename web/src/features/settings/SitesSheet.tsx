import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useQuery } from '@tanstack/react-query';
import { CircleAlert, Pencil, Trash2 } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { sitesQuery, useCreateSite, useDeleteSite, useUpdateSite } from '@/api/queries/sites';
import type { Org, Site } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';

export function SitesSheet({ org, onClose }: { org: Org | null; onClose: () => void }) {
  const me = useMe();
  const orgId = org?.id ?? '';
  const q = useQuery({ ...sitesQuery(orgId), enabled: !!org });
  const create = useCreateSite(orgId);
  const update = useUpdateSite(orgId);
  const del = useDeleteSite(orgId);
  const canWrite = !!org && can(me, 'sites:write', org.id);
  const [name, setName] = useState('');
  const [renaming, setRenaming] = useState<{ id: string; name: string } | null>(null);
  const [deleting, setDeleting] = useState<Site | null>(null);
  const [error, setError] = useState<string | null>(null);
  const dirty = name.trim() !== '' || renaming !== null;
  const newSiteRef = useRef<HTMLInputElement>(null);

  // A different org opening in the same mounted sheet (or the sheet
  // closing, org -> null) should not carry over a half-typed add/rename
  // or a stale error from the previous org.
  useEffect(() => {
    setName('');
    setRenaming(null);
    setError(null);
  }, [org?.id]);

  const run = async (fn: () => Promise<unknown>) => {
    setError(null);
    try {
      await fn();
      return true;
    } catch (e) {
      setError(errorMessage(e));
      return false;
    }
  };
  const add = async (e: FormEvent) => {
    e.preventDefault();
    if (await run(() => create.mutateAsync(name.trim()))) setName('');
  };
  const rename = async (e: FormEvent) => {
    e.preventDefault();
    if (renaming && (await run(() => update.mutateAsync({ id: renaming.id, name: renaming.name.trim() })))) setRenaming(null);
  };

  return (
    <Sheet open={org !== null} form dirty={dirty} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="grid content-start gap-4 sm:max-w-md">
        <SheetHeader>
          <SheetTitle>Sites of {org?.name}</SheetTitle>
        </SheetHeader>
        {q.isPending && <p className="text-sm text-ink-muted">Loading…</p>}
        {q.isError && (
          <p role="alert" className="text-xs">
            {errorMessage(q.error)}
          </p>
        )}
        {q.data?.length === 0 && (
          <EmptyState message="No sites yet.">
            {canWrite && (
              <Button size="sm" variant="outline" onClick={() => newSiteRef.current?.focus()}>
                Add a site
              </Button>
            )}
          </EmptyState>
        )}
        <ul className="grid">
          {(q.data ?? []).map((s) => (
            <li key={s.id} className="flex h-9 items-center gap-2 border-b border-border text-sm">
              {renaming?.id === s.id ? (
                <form onSubmit={rename} className="flex flex-1 gap-2">
                  <Input aria-label={`Name of ${s.name}`} value={renaming.name} autoFocus onChange={(e) => setRenaming({ ...renaming, name: e.target.value })} />
                  <Button type="submit" size="sm" disabled={!renaming.name.trim() || update.isPending}>
                    Save
                  </Button>
                </form>
              ) : (
                <>
                  <span className="truncate">{s.name}</span>
                  {canWrite && (
                    <span className="ml-auto flex">
                      <Button variant="ghost" size="icon" aria-label={`Rename ${s.name}`} onClick={() => setRenaming({ id: s.id, name: s.name })}>
                        <Pencil className="size-4" aria-hidden />
                      </Button>
                      <Button variant="ghost" size="icon" aria-label={`Delete ${s.name}`} onClick={() => setDeleting(s)}>
                        <Trash2 className="size-4" aria-hidden />
                      </Button>
                    </span>
                  )}
                </>
              )}
            </li>
          ))}
        </ul>
        {canWrite && (
          <form onSubmit={add} className="flex gap-2">
            <Input ref={newSiteRef} aria-label="New site" placeholder="Berlin" value={name} maxLength={100} onChange={(e) => setName(e.target.value)} />
            <Button type="submit" disabled={!name.trim() || create.isPending}>
              Add
            </Button>
          </form>
        )}
        {error && (
          <p role="alert" className="flex items-center gap-1 text-xs">
            <CircleAlert className="size-3.5 text-failed" aria-hidden />
            {error}
          </p>
        )}
        <ConfirmDestructive
          open={deleting !== null}
          onOpenChange={(o) => !o && setDeleting(null)}
          title={`Delete ${deleting?.name ?? ''}`}
          consequence={`Role bindings scoped to this site are removed with it. Clients at this site are kept but detached from it.${
            deleting && deleting.clientCount > 0
              ? ` ${deleting.clientCount} ${deleting.clientCount === 1 ? 'client' : 'clients'} will be detached from this site.`
              : ''
          }`}
          confirmText={deleting?.name ?? ''}
          actionLabel="Delete"
          onConfirm={() => del.mutateAsync(deleting!.id)}
        />
      </SheetContent>
    </Sheet>
  );
}
