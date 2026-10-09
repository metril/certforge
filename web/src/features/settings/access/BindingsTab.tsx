import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { KeyRound, Plus, Search, Trash2, User, Users } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { apiKeysQuery } from '@/api/queries/apiKeys';
import { useRefreshMe } from '@/api/queries/auth';
import { bindingsQuery, useDeleteBinding } from '@/api/queries/bindings';
import type { ApiKey, Me, RoleBinding, SubjectType, UserDetail } from '@/api/types';
import { usersQuery } from '@/api/queries/users';
import { Combobox } from '@/components/Combobox';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { columnHelper, DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { SavedViews } from '@/components/SavedViews';
import { SegmentedControl } from '@/components/SegmentedControl';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { scopeLabel } from '@/lib/apiKeys';
import { useMe } from '@/lib/org';
import { failedWithoutData } from '@/lib/queryState';
import { can, canAnywhere } from '@/lib/permissions';
import { fmtDate } from '@/lib/time';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { useUrlText } from '@/lib/useUrlText';
import { cn } from '@/lib/utils';
import { BindingSheet, ROLE_LABEL } from './BindingSheet';
import { IconButton } from '@/components/IconButton';

const col = columnHelper<RoleBinding>();
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

type Resolved = { primary: string; secondary?: string; mono?: boolean };

// Fix round 1 (review): resolve a binding's subject to a human-friendly
// display instead of the raw RoleBinding.subjectLabel alone — a user shows
// their display name plus email (looked up by id in usersQuery, falling
// back to the raw id in mono if the user isn't in that list), an oidc_group
// shows the group name in mono (no lookup: the subject *is* the label), and
// an apikey shows the key's name plus its raw id in mono (looked up in
// apiKeysQuery, same id fallback).
function resolveSubject(b: RoleBinding, users: Map<string, UserDetail>, keys: Map<string, ApiKey>): Resolved {
  if (b.subjectType === 'user') {
    const u = users.get(b.subject);
    return u ? { primary: u.displayName, secondary: u.email ?? undefined } : { primary: b.subject, mono: true };
  }
  if (b.subjectType === 'oidc_group') {
    return { primary: b.subject, mono: true };
  }
  const k = keys.get(b.subject);
  return k ? { primary: k.name, secondary: b.subject } : { primary: b.subject, mono: true };
}

function matchesQuery(b: RoleBinding, resolved: Resolved, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  return [resolved.primary, resolved.secondary, b.subject, b.subjectLabel].some((s) => s?.toLowerCase().includes(needle));
}

function SubjectDisplay({ type, resolved }: { type: SubjectType; resolved: Resolved }) {
  const Icon = TYPE_ICON[type];
  return (
    <span className="flex min-w-0 items-center gap-2">
      <Icon className="size-4 shrink-0 text-ink-muted" aria-label={type} />
      <span className={cn('truncate', resolved.mono && 'font-mono text-xs')}>{resolved.primary}</span>
      {resolved.secondary && <span className="truncate font-mono text-xs text-ink-muted">{resolved.secondary}</span>}
    </span>
  );
}

function BindingCard({ b, me, resolved, onRemove }: { b: RoleBinding; me: Me; resolved: Resolved; onRemove: () => void }) {
  return (
    <div className="grid gap-2 rounded-md border border-border bg-panel p-3">
      <div className="flex items-center justify-between gap-2">
        <SubjectDisplay type={b.subjectType} resolved={resolved} />
        {canManage(me, b) && (
          <IconButton variant="ghost" size="icon" label={`Remove ${b.subjectLabel} ${b.role}`} onClick={onRemove}>
            <Trash2 className="size-4" aria-hidden />
          </IconButton>
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

function BindingCardSkeleton() {
  return (
    <div className="grid gap-2 rounded-md border border-border bg-panel p-3" aria-hidden>
      <div className="h-4 w-1/2 animate-pulse rounded-sm bg-subtle" />
      <div className="h-3 w-1/3 animate-pulse rounded-sm bg-subtle" />
      <div className="h-3 w-1/4 animate-pulse rounded-sm bg-subtle" />
    </div>
  );
}

export function BindingsTab() {
  const me = useMe();
  const search = useSearch({ from: '/_app/settings/$section' });
  const navigate = useNavigate({ from: '/settings/$section' });
  const q = useQuery(bindingsQuery({ subjectType: search.type, orgId: search.orgId }));
  const users = useQuery(usersQuery);
  const keys = useQuery(apiKeysQuery());
  const del = useDeleteBinding();
  const refreshMe = useRefreshMe();
  const [adding, setAdding] = useState(false);
  const [removing, setRemoving] = useState<RoleBinding | null>(null);
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const [text, setText] = useUrlText(search.q, (v) => void navigate({ search: (prev) => ({ ...prev, q: v }), replace: true }));

  const userById = useMemo(() => new Map((users.data ?? []).map((u) => [u.id, u])), [users.data]);
  const keyById = useMemo(() => new Map((keys.data ?? []).map((k) => [k.id, k])), [keys.data]);
  const resolvedRows = useMemo(
    () =>
      (q.data ?? [])
        .map((b) => ({ b, resolved: resolveSubject(b, userById, keyById) }))
        .filter(({ b, resolved }) => matchesQuery(b, resolved, search.q ?? '')),
    [q.data, userById, keyById, search.q],
  );
  const tableData = useMemo(() => resolvedRows.map((r) => r.b), [resolvedRows]);

  // M4: clears every filter (type, org, and the debounced search text, plus
  // its own local buffer so the debounce doesn't re-push the old value).
  const clearFilters = () => {
    setText('');
    void navigate({ search: (prev) => ({ ...prev, q: undefined, type: undefined, orgId: undefined }) });
  };

  const columns = useMemo(
    () => [
      col.accessor('subjectLabel', {
        header: 'Subject',
        meta: { help: 'binding.subjectType' },
        cell: ({ row }) => (
          <SubjectDisplay type={row.original.subjectType} resolved={resolveSubject(row.original, userById, keyById)} />
        ),
      }),
      col.accessor('role', { header: 'Role', meta: { help: 'binding.role' }, cell: (c) => ROLE_LABEL[c.getValue()] }),
      col.accessor('orgId', { header: 'Scope', meta: { help: 'binding.scope' }, cell: (c) => scopeLabel(me, c.getValue()) }),
      col.accessor('createdAt', { header: 'Added', cell: (c) => fmtDate(c.getValue()) }),
      col.display({
        id: 'actions',
        header: '',
        cell: ({ row }) =>
          canManage(me, row.original) && (
            <IconButton
              variant="ghost"
              size="icon"
              label={`Remove ${row.original.subjectLabel} ${row.original.role}`}
              onClick={(e) => {
                e.stopPropagation();
                setRemoving(row.original);
              }}
            >
              <Trash2 className="size-4" aria-hidden />
            </IconButton>
          ),
      }),
    ],
    [me, userById, keyById],
  );

  const add = (canAnywhere(me, 'bindings:write') || canAnywhere(me, 'apikeys:write')) && (
    <Button onClick={() => setAdding(true)}>
      <Plus className="size-4" aria-hidden />
      Add binding
    </Button>
  );

  const orgOptions = me.orgs.map((o) => ({ value: o.id, label: o.name }));

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
        <Combobox
          aria-label="Org"
          value={search.orgId}
          onChange={(v) => void navigate({ search: (prev) => ({ ...prev, orgId: v }), replace: true })}
          options={orgOptions}
          placeholder="Filter by org"
          emptyText="No org matches."
        />
        <div className="ml-auto">{add}</div>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative w-72">
          <Search className="absolute left-2 top-2.5 size-4 text-ink-muted" aria-hidden />
          <Input aria-label="Search bindings" className="pl-8" placeholder="Ann" value={text} onChange={(e) => setText(e.target.value)} />
        </div>
        <SavedViews list="bindings" current={{ q: search.q, type: search.type, orgId: search.orgId }} onApply={(s) => void navigate({ search: (prev) => ({ ...prev, ...s }) })} />
      </div>
      {failedWithoutData(q) ? (
        <ErrorState message={`Couldn't load bindings. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />
      ) : q.data && q.data.length === 0 ? (
        <EmptyState message="No role bindings match.">{add}</EmptyState>
      ) : q.data && resolvedRows.length === 0 ? (
        <EmptyState message="No role bindings match this search.">
          <Button variant="outline" onClick={clearFilters}>
            Clear filters
          </Button>
        </EmptyState>
      ) : isMdUp ? (
        <DataTable
          ariaLabel="Role bindings"
          data={tableData}
          columns={columns}
          getRowId={(b) => b.id}
          skeletonRows={q.isPending ? 3 : undefined}
        />
      ) : q.isPending ? (
        <div className="grid gap-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <BindingCardSkeleton key={i} />
          ))}
        </div>
      ) : (
        <div className="grid gap-2">
          {resolvedRows.map(({ b, resolved }) => (
            <BindingCard key={b.id} b={b} me={me} resolved={resolved} onRemove={() => setRemoving(b)} />
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
        onConfirm={async () => {
          const r = removing!;
          await del.mutateAsync(r.id);
          // M5: removing the caller's own binding changes what `can` allows
          // right away (see BindingSheet's matching case on create).
          if (r.subjectType === 'user' && r.subject === me.user.id) await refreshMe();
        }}
      />
    </div>
  );
}
