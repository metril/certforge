import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Pencil, Plus, Trash2 } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { useRefreshMe } from '@/api/queries/auth';
import { orgsQuery, useDeleteOrg } from '@/api/queries/orgs';
import type { Org } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { OrgSheet } from './OrgSheet';
import { SitesSheet } from './SitesSheet';

/** Organizations and their sites for Settings → General. */
export function OrgsList() {
  const me = useMe();
  const q = useQuery(orgsQuery);
  const del = useDeleteOrg();
  const refreshMe = useRefreshMe();
  const [editing, setEditing] = useState<Org | 'new' | null>(null);
  const [deleting, setDeleting] = useState<Org | null>(null);
  const [sitesOf, setSitesOf] = useState<Org | null>(null);
  const canWrite = can(me, 'orgs:write');
  return (
    <section aria-labelledby="orgs-title" className="mt-8 max-w-[720px]">
      <div className="mb-2 flex items-center gap-2">
        <h3 id="orgs-title" className="flex items-center gap-1.5 text-sm font-semibold">
          Organizations
          <HelpTip id="settings.orgs" />
        </h3>
        {canWrite && (
          <Button size="sm" variant="outline" className="ml-auto" onClick={() => setEditing('new')}>
            <Plus className="size-4" aria-hidden />
            New organization
          </Button>
        )}
      </div>
      {q.isPending && <p className="text-sm text-ink-muted">Loading…</p>}
      {q.isError && (
        <p role="alert" className="text-xs">
          {errorMessage(q.error)}
        </p>
      )}
      <ul className="grid">
        {(q.data ?? []).map((o) => (
          <li key={o.id} className="flex h-9 items-center gap-2 border-b border-border text-sm">
            <span className="truncate">{o.name}</span>
            <span className="font-mono text-xs text-ink-muted">{o.slug}</span>
            <span className="ml-auto flex items-center">
              {can(me, 'sites:read', o.id) && (
                <Button variant="ghost" size="sm" aria-label={`Sites of ${o.name}`} onClick={() => setSitesOf(o)}>
                  Sites
                </Button>
              )}
              {canWrite && (
                <>
                  <Button variant="ghost" size="icon" aria-label={`Rename ${o.name}`} onClick={() => setEditing(o)}>
                    <Pencil className="size-4" aria-hidden />
                  </Button>
                  <Button variant="ghost" size="icon" aria-label={`Delete ${o.name}`} onClick={() => setDeleting(o)}>
                    <Trash2 className="size-4" aria-hidden />
                  </Button>
                </>
              )}
            </span>
          </li>
        ))}
      </ul>
      <OrgSheet org={editing} onClose={() => setEditing(null)} onSaved={refreshMe} />
      <SitesSheet org={sitesOf} onClose={() => setSitesOf(null)} />
      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete ${deleting?.name ?? ''}`}
        consequence="The org and its sites are removed; anything still in it blocks the delete."
        confirmText={deleting?.slug ?? ''}
        actionLabel="Delete"
        onConfirm={async () => {
          await del.mutateAsync(deleting!.id);
          await refreshMe();
        }}
      />
    </section>
  );
}
