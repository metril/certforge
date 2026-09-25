import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { createColumnHelper } from '@tanstack/react-table';
import { Search } from 'lucide-react';
import { toast } from 'sonner';
import { errorMessage } from '@/api/errors';
import { usersQuery, useUpdateUser } from '@/api/queries/users';
import type { UserDetail } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { SavedViews } from '@/components/SavedViews';
import { Badge } from '@/components/ui/badge';
import { Input } from '@/components/ui/input';
import { Switch } from '@/components/ui/switch';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { help } from '@/lib/help';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { fmtDateTime } from '@/lib/time';
import { useMediaQuery } from '@/lib/useMediaQuery';

const col = createColumnHelper<UserDetail>();

function issuerHost(u: UserDetail): string {
  if (u.localAdmin || !u.oidcIssuer) return 'Local';
  try {
    return new URL(u.oidcIssuer).host;
  } catch {
    return u.oidcIssuer;
  }
}

function matches(u: UserDetail, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  return (
    u.displayName.toLowerCase().includes(needle) ||
    (u.email?.toLowerCase().includes(needle) ?? false) ||
    u.groups.some((g) => g.toLowerCase().includes(needle))
  );
}

// Status switch + label, shared between the table column and the card row
// below `md` (controller ruling D5). Kept a plain function component (not a
// column cell factory) so both layouts render exactly the same markup.
function StatusControl({
  u,
  canWrite,
  isSelf,
  pending,
  onDisable,
  onEnable,
}: {
  u: UserDetail;
  canWrite: boolean;
  isSelf: boolean;
  pending: boolean;
  onDisable: () => void;
  onEnable: () => void;
}) {
  const control = (
    <Switch
      checked={!u.disabled}
      disabled={!canWrite || isSelf || pending}
      aria-label={`${u.displayName} active`}
      onClick={(e) => e.stopPropagation()}
      onCheckedChange={(on) => (on ? onEnable() : onDisable())}
    />
  );
  return (
    <span className="flex items-center gap-2">
      {isSelf ? (
        <Tooltip>
          <TooltipTrigger asChild>
            <span>{control}</span>
          </TooltipTrigger>
          <TooltipContent side="top">{help['user.self'].text}</TooltipContent>
        </Tooltip>
      ) : (
        control
      )}
      <span className="text-sm">{u.disabled ? 'Disabled' : 'Active'}</span>
    </span>
  );
}

function UserCard({
  u,
  canWrite,
  isSelf,
  pending,
  onDisable,
  onEnable,
}: {
  u: UserDetail;
  canWrite: boolean;
  isSelf: boolean;
  pending: boolean;
  onDisable: () => void;
  onEnable: () => void;
}) {
  return (
    <div className="grid gap-2 rounded-md border border-border bg-panel p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="flex min-w-0 items-center gap-2">
          <span className="truncate font-semibold">{u.displayName}</span>
          {u.localAdmin && <Badge variant="outline">Local admin</Badge>}
        </span>
        <StatusControl u={u} canWrite={canWrite} isSelf={isSelf} pending={pending} onDisable={onDisable} onEnable={onEnable} />
      </div>
      <span className="font-mono text-xs text-ink-muted">{u.email ?? '–'}</span>
      <div className="flex items-center justify-between text-xs text-ink-muted">
        <span className="font-mono">{issuerHost(u)}</span>
        <span>{u.lastLogin ? fmtDateTime(u.lastLogin) : 'Never signed in'}</span>
      </div>
      {u.groups.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {u.groups.map((g) => (
            <Badge key={g} variant="secondary" className="font-mono">
              {g}
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}

export function UsersTab() {
  const me = useMe();
  const q = useQuery(usersQuery);
  const update = useUpdateUser();
  const [confirm, setConfirm] = useState<UserDetail | null>(null);
  const canWrite = can(me, 'users:write');
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const search = useSearch({ from: '/_app/settings/$section' });
  const navigate = useNavigate({ from: '/settings/$section' });
  const [text, setText] = useState(search.q ?? '');

  // Debounced, URL-synced text filter (controller ruling D5), mirroring the
  // certificates list's own `q` debounce (features/certificates/list/CertificatesPage.tsx).
  const pushedQ = useRef(search.q ?? '');
  useEffect(() => {
    const urlQ = search.q ?? '';
    if (urlQ !== pushedQ.current) {
      pushedQ.current = urlQ;
      if (urlQ !== text) setText(urlQ);
      return;
    }
    if (text === urlQ) return;
    const t = window.setTimeout(() => {
      pushedQ.current = text;
      void navigate({ search: (prev) => ({ ...prev, q: text || undefined }), replace: true });
    }, 250);
    return () => window.clearTimeout(t);
  }, [text, search.q, navigate]);

  const rows = useMemo(() => (q.data ?? []).filter((u) => matches(u, search.q ?? '')), [q.data, search.q]);

  const runDisable = useCallback((u: UserDetail) => setConfirm(u), []);
  const runEnable = useCallback(
    (u: UserDetail) => update.mutate({ id: u.id, disabled: false }, { onError: (err) => toast.error(errorMessage(err)) }),
    [update],
  );

  const columns = useMemo(
    () => [
      col.accessor('displayName', {
        header: 'Name',
        cell: ({ row }) => (
          <span className="flex items-center gap-2">
            <span className="truncate">{row.original.displayName}</span>
            {row.original.localAdmin && <Badge variant="outline">Local admin</Badge>}
          </span>
        ),
      }),
      col.accessor('email', { header: 'Email', cell: (c) => <span className="font-mono text-xs">{c.getValue() ?? '–'}</span> }),
      col.display({ id: 'source', header: 'Source', meta: { help: 'user.source' }, cell: ({ row }) => <span className="font-mono text-xs">{issuerHost(row.original)}</span> }),
      col.accessor('groups', {
        header: 'Groups',
        meta: { help: 'user.groups' },
        cell: (c) => {
          const g = c.getValue();
          return (
            <span className="flex flex-wrap gap-1">
              {g.slice(0, 3).map((x) => (
                <Badge key={x} variant="secondary" className="font-mono">
                  {x}
                </Badge>
              ))}
              {g.length > 3 && <Badge variant="secondary">+{g.length - 3}</Badge>}
            </span>
          );
        },
      }),
      col.accessor('lastLogin', { header: 'Last sign-in', cell: (c) => (c.getValue() ? fmtDateTime(c.getValue()!) : '–') }),
      col.display({
        id: 'status',
        header: 'Status',
        meta: { help: 'user.status' },
        cell: ({ row }) => {
          const u = row.original;
          const self = u.id === me.user.id;
          return (
            <StatusControl
              u={u}
              canWrite={canWrite}
              isSelf={self}
              pending={update.isPending}
              onDisable={() => runDisable(u)}
              onEnable={() => runEnable(u)}
            />
          );
        },
      }),
    ],
    [me.user.id, canWrite, update.isPending, runDisable, runEnable],
  );

  if (q.isPending) return <p className="text-sm text-ink-muted">Loading…</p>;
  if (q.isError) return <ErrorState message={`Couldn't load users. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />;

  return (
    <>
      <div className="mb-3 flex flex-wrap items-center gap-3">
        <div className="relative w-72">
          <Search className="absolute left-2 top-2.5 size-4 text-ink-muted" aria-hidden />
          <Input aria-label="Search users" className="pl-8" placeholder="Ann" value={text} onChange={(e) => setText(e.target.value)} />
        </div>
        <SavedViews list="users" current={{ q: search.q }} onApply={(s) => void navigate({ search: (prev) => ({ ...prev, ...s }) })} />
      </div>
      {(q.data ?? []).length === 0 ? (
        <EmptyState message="No users have signed in yet." />
      ) : rows.length === 0 ? (
        <EmptyState message="No users match this search." />
      ) : isMdUp ? (
        <DataTable ariaLabel="Users" data={rows} columns={columns} getRowId={(u) => u.id} />
      ) : (
        <div className="grid gap-2">
          {rows.map((u) => (
            <UserCard
              key={u.id}
              u={u}
              canWrite={canWrite}
              isSelf={u.id === me.user.id}
              pending={update.isPending}
              onDisable={() => runDisable(u)}
              onEnable={() => runEnable(u)}
            />
          ))}
        </div>
      )}
      <ConfirmDestructive
        open={confirm !== null}
        onOpenChange={(o) => !o && setConfirm(null)}
        title={`Disable ${confirm?.displayName ?? ''}`}
        consequence="They are signed out everywhere at once and their API keys stop working."
        confirmText={confirm?.displayName ?? ''}
        actionLabel="Disable"
        onConfirm={() => update.mutateAsync({ id: confirm!.id, disabled: true })}
      />
    </>
  );
}
