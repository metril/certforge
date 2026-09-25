import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { createColumnHelper } from '@tanstack/react-table';
import { KeyRound, Plus, Trash2, User, Users } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { bindingsQuery, useDeleteBinding } from '@/api/queries/bindings';
import type { Me, RoleBinding, SubjectType } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { useMe } from '@/lib/org';
import { can, canAnywhere } from '@/lib/permissions';
import { fmtDate } from '@/lib/time';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { BindingSheet, ROLE_LABEL, scopeLabel } from './BindingSheet';

const col = createColumnHelper<RoleBinding>();
const TYPE_ICON = { user: User, oidc_group: Users, apikey: KeyRound } as const;
type TypeFilter = 'all' | SubjectType;

// Mirrors deleteRoleBinding's own permission rule (2A operationId
// description): user/oidc_group subjects need bindings:write (oidc_group
// always globally); apikey subjects need apikeys:write at the key's own
// scope instead.
function canManage(me: Pick<Me, 'bindings'>, b: RoleBinding): boolean {
  if (b.subjectType === 'apikey') return can(me, 'apikeys:write', b.orgId);
  if (b.subjectType === 'oidc_group') return can(me, 'bindings:write', null);
  return can(me, 'bindings:write', b.orgId);
}

function BindingCard({ b, me, onRemove }: { b: RoleBinding; me: Me; onRemove: () => void }) {
  const Icon = TYPE_ICON[b.subjectType];
  return (
    <div className="grid gap-2 rounded-md border border-border bg-panel p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="flex min-w-0 items-center gap-2">
          <Icon className="size-4 shrink-0 text-ink-muted" aria-label={b.subjectType} />
          <span className={b.subjectType === 'user' ? 'truncate' : 'truncate font-mono text-xs'}>{b.subjectLabel}</span>
        </span>
        {canManage(me, b) && (
          <Button variant="ghost" size="icon" aria-label={`Remove ${b.subjectLabel} ${b.role}`} onClick={onRemove}>
            <Trash2 className="size-4" aria-hidden />
          </Button>
        )}
      </div>
      <div className="flex items-center justify-between text-xs text-ink-muted">
        <span>{ROLE_LABEL[b.role]}</span>
        <span>{scopeLabel(me, b.orgId)}</span>
      </div>
      <span className="text-xs text-ink-muted">Added {fmtDate(b.createdAt)}</span>
    </div>
  );
}

export function BindingsTab() {
  const me = useMe();
  const search = useSearch({ from: '/_app/settings/$section' });
  const navigate = useNavigate({ from: '/settings/$section' });
  const q = useQuery(bindingsQuery(search.type ? { subjectType: search.type } : {}));
  const del = useDeleteBinding();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<RoleBinding | null>(null);
  const isMdUp = useMediaQuery('(min-width: 768px)');

  const columns = useMemo(
    () => [
      col.accessor('subjectLabel', {
        header: 'Subject',
        meta: { help: 'binding.subjectType' },
        cell: ({ row }) => {
          const Icon = TYPE_ICON[row.original.subjectType];
          return (
            <span className="flex min-w-0 items-center gap-2">
              <Icon className="size-4 shrink-0 text-ink-muted" aria-label={row.original.subjectType} />
              <span className={row.original.subjectType === 'user' ? 'truncate' : 'truncate font-mono text-xs'}>{row.original.subjectLabel}</span>
            </span>
          );
        },
      }),
      col.accessor('role', { header: 'Role', meta: { help: 'binding.role' }, cell: (c) => ROLE_LABEL[c.getValue()] }),
      col.accessor('orgId', { header: 'Scope', meta: { help: 'binding.scope' }, cell: (c) => scopeLabel(me, c.getValue()) }),
      col.accessor('createdAt', { header: 'Added', cell: (c) => fmtDate(c.getValue()) }),
      col.display({
        id: 'actions',
        header: '',
        cell: ({ row }) =>
          canManage(me, row.original) && (
            <Button
              variant="ghost"
              size="icon"
              aria-label={`Remove ${row.original.subjectLabel} ${row.original.role}`}
              onClick={(e) => {
                e.stopPropagation();
                setRemoving(row.original);
              }}
            >
              <Trash2 className="size-4" aria-hidden />
            </Button>
          ),
      }),
    ],
    [me],
  );

  const add = (canAnywhere(me, 'bindings:write') || canAnywhere(me, 'apikeys:write')) && (
    <Button onClick={() => setAdding(true)}>
      <Plus className="size-4" aria-hidden />
      Add binding
    </Button>
  );

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <SegmentedControl<TypeFilter>
          aria-label="Subject type filter"
          value={search.type ?? 'all'}
          onChange={(v) => void navigate({ search: (prev) => ({ ...prev, type: v === 'all' ? undefined : v }), replace: true })}
          options={[
            { value: 'all', label: 'All' },
            { value: 'user', label: 'Users' },
            { value: 'oidc_group', label: 'Groups' },
            { value: 'apikey', label: 'API keys' },
          ]}
        />
        <div className="ml-auto">{add}</div>
      </div>
      {q.isError ? (
        <ErrorState message={`Couldn't load bindings. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />
      ) : q.data && q.data.length === 0 ? (
        <EmptyState message="No role bindings match.">{add}</EmptyState>
      ) : isMdUp ? (
        <DataTable ariaLabel="Role bindings" data={q.data ?? []} columns={columns} getRowId={(b) => b.id} skeletonRows={q.isPending ? 3 : undefined} />
      ) : (
        <div className="grid gap-2">
          {(q.data ?? []).map((b) => (
            <BindingCard key={b.id} b={b} me={me} onRemove={() => setRemoving(b)} />
          ))}
        </div>
      )}
      <BindingSheet open={adding} onOpenChange={setAdding} />
      <ConfirmDestructive
        open={removing !== null}
        onOpenChange={(o) => !o && setRemoving(null)}
        title={`Remove ${removing?.subjectLabel ?? ''}`}
        consequence={`${removing?.subjectLabel ?? ''} loses the ${removing ? ROLE_LABEL[removing.role] : ''} role in ${removing ? scopeLabel(me, removing.orgId) : ''} on their next request.`}
        confirmText={removing?.subjectLabel ?? ''}
        actionLabel="Remove"
        onConfirm={() => del.mutateAsync(removing!.id)}
      />
    </div>
  );
}
