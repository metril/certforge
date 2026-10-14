import { Fragment, useEffect, useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { Plus, StepBack, StepForward } from 'lucide-react';
import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { metaSchemasQuery } from '@/api/queries/dns';
import { actionGroupsQuery, actionsQuery, useDeleteAction, useDeleteActionGroup } from '@/api/queries/delivery';
import type { Action, ActionGroup } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { EntityLink } from '@/components/EntityLink';
import { PrimaryCell } from '@/components/PrimaryCell';
import { PermissionTip } from '@/components/PermissionTip';
import { RunsOnChip } from '@/components/RunsOnChip';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from '@/components/ui/table';
import { Tabs, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { PHASE_LABEL } from '@/lib/clientStatus';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { failedWithoutData } from '@/lib/queryState';
import { cn } from '@/lib/utils';
import { ActionSheet } from './ActionSheet';
import { GroupSheet } from './GroupSheet';
import { RowActions, UsedBy } from './RowActions';

const stickyCol = 'sticky left-0 z-10 bg-panel';

export function ActionsPage() {
  const org = useOrg();
  const me = useMe();
  const canWrite = can(me, 'delivery:write', org.id);
  const { tab = 'actions', edit } = useSearch({ from: '/_app/o/$org/delivery/actions' });
  const navigate = useNavigate({ from: '/o/$org/delivery/actions' });
  const q = useQuery(actionsQuery(org.id));
  const gq = useQuery(actionGroupsQuery(org.id));
  const metaQ = useQuery(metaSchemasQuery);
  const delAction = useDeleteAction(org.id);
  const delGroup = useDeleteActionGroup(org.id);
  const [deleting, setDeleting] = useState<Action | null>(null);
  const [deletingGroup, setDeletingGroup] = useState<ActionGroup | null>(null);
  const kinds = metaQ.data?.actions;
  const kindName = useMemo(() => new Map((kinds ?? []).map((k) => [k.code, k.name])), [kinds]);
  const actions = q.data ?? [];
  const groups = gq.data ?? [];
  const active = tab === 'groups' ? gq : q;
  const items: { id: string }[] = tab === 'groups' ? groups : actions;
  const openSheet = (id: string | undefined) => void navigate({ search: (s) => ({ ...s, edit: id }), replace: id === undefined });
  const setTab = (t: string) => void navigate({ search: { tab: t === 'groups' ? 'groups' : undefined }, replace: true });
  // A hand-edited or stale `?edit=<id>` that no longer resolves must not leave
  // the page silently doing nothing — drop it from the URL and say why.
  useEffect(() => {
    if (active.isPending || !edit || edit === 'new') return;
    if (!items.some((h) => h.id === edit)) {
      openSheet(undefined);
      toast.error(tab === 'groups' ? 'Action group not found.' : 'Action not found.');
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [edit, active.isPending, tab, items.map((h) => h.id).join(',')]);
  const editing = tab === 'actions' ? actions.find((a) => a.id === edit) : undefined;
  const editingGroup = tab === 'groups' ? groups.find((g) => g.id === edit) : undefined;
  const noun = tab === 'groups' ? 'group' : 'action';
  const add = (
    <PermissionTip allowed={canWrite} action="delivery:write">
      <Button disabled={!canWrite || (tab === 'actions' && !kinds)} onClick={() => openSheet('new')}>
        <Plus className="size-4" aria-hidden />
        New {noun}
      </Button>
    </PermissionTip>
  );
  const actionName = (id: string) => actions.find((a) => a.id === id)?.name ?? 'Unknown action';

  return (
    <div className="grid gap-4">
      <Tabs value={tab} onValueChange={setTab}>
        <div className="flex items-center gap-2">
          <TabsList aria-label="Library">
            <TabsTrigger value="actions">Actions</TabsTrigger>
            <TabsTrigger value="groups">Groups</TabsTrigger>
          </TabsList>
          {tab === 'groups' && <HelpTip id="action.group" />}
        </div>
      </Tabs>
      {active.isPending ? (
        <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>
      ) : failedWithoutData(active) ? (
        <ErrorState message={`Couldn't load ${noun}s. ${errorMessage(active.error)}`} onRetry={() => void active.refetch()} />
      ) : items.length === 0 ? (
        <EmptyState message={tab === 'groups' ? 'No action groups yet.' : 'No actions yet.'}>{add}</EmptyState>
      ) : tab === 'actions' ? (
        <>
          <div className="flex justify-end">{add}</div>
          <Table aria-label="Actions" className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className={cn('w-56', stickyCol)}>Name</TableHead>
                <TableHead>
                  <span className="inline-flex items-center gap-1">
                    Kind <HelpTip id="action.kind" />
                  </span>
                </TableHead>
                <TableHead className="w-24">Phase</TableHead>
                <TableHead className="w-28">Runs on</TableHead>
                <TableHead className="w-24">Timeout</TableHead>
                <TableHead className="w-28">Used by</TableHead>
                <TableHead className="w-20">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {actions.map((a) => (
                <TableRow key={a.id}>
                  <TableCell className={cn('py-1.5', stickyCol)}>
                    <PrimaryCell primary={a.name} meta={a.optional ? ['Optional'] : []} />
                  </TableCell>
                  <TableCell className="py-1 text-sm">{kindName.get(a.kind) ?? a.kind}</TableCell>
                  <TableCell className="py-1">
                    <ToneChip tone="neutral" icon={a.phase === 'pre_deploy' ? StepBack : StepForward} label={a.phase === 'pre_deploy' ? 'Pre' : 'Post'} aria-label={PHASE_LABEL[a.phase]} />
                  </TableCell>
                  <TableCell className="py-1">
                    <RunsOnChip mode={a.runsOn} />
                  </TableCell>
                  <TableCell className="py-1 text-sm">{a.timeoutSeconds} s</TableCell>
                  <TableCell className="py-1">
                    <UsedBy count={a.grantCount} filter={{ actionId: a.id }} />
                  </TableCell>
                  <TableCell className="py-1 text-right">
                    <RowActions name={a.name} grantCount={a.grantCount} canWrite={canWrite} onOpen={() => openSheet(a.id)} onDelete={() => setDeleting(a)} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </>
      ) : (
        <>
          <div className="flex justify-end">{add}</div>
          <Table aria-label="Action groups" className="table-fixed">
            <TableHeader>
              <TableRow>
                <TableHead className={cn('w-56', stickyCol)}>Name</TableHead>
                <TableHead>Actions</TableHead>
                <TableHead className="w-28">Used by</TableHead>
                <TableHead className="w-20">
                  <span className="sr-only">Actions</span>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {groups.map((g) => (
                <TableRow key={g.id}>
                  <TableCell className={cn('py-1.5', stickyCol)}>
                    <PrimaryCell primary={g.name} meta={[`${g.actionIds.length} ${g.actionIds.length === 1 ? 'action' : 'actions'}`]} />
                  </TableCell>
                  <TableCell className="truncate py-1 text-sm text-ink-muted">{g.actionIds.map((id, i) => (
                      <Fragment key={`${id}-${i}`}>
                        {i > 0 && ' → '}
                        <EntityLink kind="action" id={id}>
                          {actionName(id)}
                        </EntityLink>
                      </Fragment>
                    ))}
                  </TableCell>
                  <TableCell className="py-1">
                    <UsedBy count={g.grantCount} filter={{ actionGroupId: g.id }} />
                  </TableCell>
                  <TableCell className="py-1 text-right">
                    <RowActions name={g.name} grantCount={g.grantCount} canWrite={canWrite} onOpen={() => openSheet(g.id)} onDelete={() => setDeletingGroup(g)} />
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </>
      )}
      {kinds && tab === 'actions' && ((canWrite && edit === 'new') || editing) && (
        <ActionSheet key={edit} orgId={org.id} action={editing} kinds={kinds} readOnly={!canWrite} onOpenChange={(o) => !o && openSheet(undefined)} />
      )}
      {tab === 'groups' && ((canWrite && edit === 'new') || editingGroup) && (
        <GroupSheet key={edit} orgId={org.id} group={editingGroup} actions={actions} readOnly={!canWrite} onOpenChange={(o) => !o && openSheet(undefined)} />
      )}
      <ConfirmDestructive
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title="Delete action"
        consequence="Grants and groups can no longer pick this action; its run history stays."
        confirmText={deleting?.name ?? ''}
        actionLabel="Delete"
        onConfirm={() => delAction.mutateAsync(deleting!.id)}
      />
      <ConfirmDestructive
        open={!!deletingGroup}
        onOpenChange={(o) => !o && setDeletingGroup(null)}
        title="Delete action group"
        consequence="Grants can no longer pick this group. Its actions stay."
        confirmText={deletingGroup?.name ?? ''}
        actionLabel="Delete"
        onConfirm={() => delGroup.mutateAsync(deletingGroup!.id)}
      />
    </div>
  );
}
