import { Card, CardBody, CardHeader } from '@/components/Card';
import { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useParams } from '@tanstack/react-router';
import { Pencil, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
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
  const navigate = useNavigate();
  const routeOrg = useParams({ strict: false }).org;
  const [editing, setEditing] = useState<Org | 'new' | null>(null);
  const [deleting, setDeleting] = useState<Org | null>(null);
  const [sitesOf, setSitesOf] = useState<Org | null>(null);
  const canWrite = can(me, 'orgs:write');
  return (
    <Card role="region" aria-labelledby="orgs-title" className="mt-8 max-w-[720px]">
      <CardHeader
        titleId="orgs-title"
        title={
          <span className="flex items-center gap-1.5">
            Organizations
            <HelpTip id="settings.orgs" />
          </span>
        }
        actions={
          canWrite && (
            <Button size="sm" variant="outline" onClick={() => setEditing('new')}>
              <Plus className="size-4" aria-hidden />
              New organization
            </Button>
          )
        }
      />
      <CardBody>
      {q.isPending && <p className="text-sm text-ink-muted">Loading…</p>}
      {q.isError && (
        <p role="alert" className="text-xs">
          {errorMessage(q.error)}
        </p>
      )}
      <ul className="grid">
        {(q.data ?? []).map((o) => (
          <li key={o.id} className="flex min-h-9 flex-wrap items-center gap-x-2 gap-y-0.5 border-b border-border py-1.5 text-sm md:flex-nowrap md:py-0">
            <span className="flex flex-col md:flex-row md:items-center md:gap-2">
              <span className="truncate">{o.name}</span>
              <span className="font-mono text-xs text-ink-muted">{o.slug}</span>
            </span>
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
      </CardBody>
      <OrgSheet org={editing} onClose={() => setEditing(null)} onSaved={refreshMe} />
      <SitesSheet org={sitesOf} onClose={() => setSitesOf(null)} />
      <ConfirmDestructive
        open={deleting !== null}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete ${deleting?.name ?? ''}`}
        consequence="Delete its certificates, credentials, accounts, sites, bindings and active API keys first."
        help="org.deleteCascade"
        confirmText={deleting?.slug ?? ''}
        actionLabel="Delete"
        onConfirm={async () => {
          if (!deleting) return;
          const wasActive = deleting.slug === routeOrg;
          await del.mutateAsync(deleting.id);
          try {
            await refreshMe();
          } catch (e) {
            // The delete itself already succeeded; a failed /auth/me
            // refetch is a separate, non-blocking problem — toast it
            // instead of surfacing it as a failed delete (which would
            // reopen this dialog with a misleading inline error).
            toast.error(errorMessage(e));
            return;
          }
          if (wasActive) void navigate({ to: '/' });
        }}
      />
    </Card>
  );
}
