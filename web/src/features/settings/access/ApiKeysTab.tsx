import { useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { useNavigate, useSearch } from '@tanstack/react-router';
import { createColumnHelper } from '@tanstack/react-table';
import { Ban, CircleCheck, CircleX, Plus, Search } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { apiKeysQuery, useRevokeApiKey } from '@/api/queries/apiKeys';
import type { ApiKey, ApiKeyCreated } from '@/api/types';
import { ConfirmDestructive } from '@/components/ConfirmDestructive';
import { DataTable } from '@/components/DataTable';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { SavedViews } from '@/components/SavedViews';
import { SegmentedControl } from '@/components/SegmentedControl';
import { ToneChip } from '@/components/StatusChip';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { keyState, scopeLabel } from '@/lib/apiKeys';
import { useMe } from '@/lib/org';
import { can, canAnywhere } from '@/lib/permissions';
import { fmtDate, fmtDateTime } from '@/lib/time';
import { useMediaQuery } from '@/lib/useMediaQuery';
import { ApiKeySheet } from './ApiKeySheet';
import { OneTimeSecretDialog } from './OneTimeSecretDialog';

const STATE = {
  active: { tone: 'valid', icon: CircleCheck, label: 'Active' },
  expired: { tone: 'expired', icon: CircleX, label: 'Expired' },
  revoked: { tone: 'neutral', icon: Ban, label: 'Revoked' },
} as const;

function matches(k: ApiKey, q: string): boolean {
  const needle = q.trim().toLowerCase();
  if (!needle) return true;
  return k.name.toLowerCase().includes(needle) || k.prefix.toLowerCase().includes(needle) || k.createdByName.toLowerCase().includes(needle);
}

function KeyCard({ k, canWrite, onRevoke }: { k: ApiKey; canWrite: boolean; onRevoke: () => void }) {
  const s = STATE[keyState(k)];
  return (
    <div className="grid gap-2 rounded-md border border-border bg-panel p-3">
      <div className="flex items-center justify-between gap-2">
        <span className="truncate font-semibold">{k.name}</span>
        <ToneChip tone={s.tone} icon={s.icon} label={s.label} />
      </div>
      <span className="font-mono text-xs text-ink-muted">cf_{k.prefix}_…</span>
      <div className="flex flex-wrap gap-1">
        {k.scopes.map((sc) => (
          <Badge key={sc} variant="secondary" className="font-mono">
            {sc}
          </Badge>
        ))}
      </div>
      <div className="flex items-center justify-between text-xs text-ink-muted">
        <span>{k.createdByName}</span>
        <span>{k.expiresAt ? fmtDate(k.expiresAt) : 'Never'}</span>
      </div>
      <span className="text-xs text-ink-muted">Last used {k.lastUsedAt ? fmtDateTime(k.lastUsedAt) : 'never'}</span>
      {keyState(k) === 'active' && canWrite && (
        <Button variant="ghost" size="sm" aria-label={`Revoke ${k.name}`} className="justify-self-end" onClick={onRevoke}>
          Revoke
        </Button>
      )}
    </div>
  );
}

function KeyCardSkeleton() {
  return (
    <div className="grid gap-2 rounded-md border border-border bg-panel p-3" aria-hidden>
      <div className="h-4 w-1/2 animate-pulse rounded-sm bg-subtle" />
      <div className="h-3 w-1/3 animate-pulse rounded-sm bg-subtle" />
      <div className="h-3 w-1/4 animate-pulse rounded-sm bg-subtle" />
    </div>
  );
}

const col = createColumnHelper<ApiKey>();

export function ApiKeysTab() {
  const me = useMe();
  const q = useQuery(apiKeysQuery());
  const revoke = useRevokeApiKey();
  const [creating, setCreating] = useState(false);
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);
  const [revoking, setRevoking] = useState<ApiKey | null>(null);
  const isMdUp = useMediaQuery('(min-width: 768px)');
  const search = useSearch({ from: '/_app/settings/$section' });
  const navigate = useNavigate({ from: '/settings/$section' });
  const [text, setText] = useState(search.q ?? '');

  // Debounced, URL-synced text filter (controller ruling D5), same contract
  // as UsersTab's and BindingsTab's own `q` debounce.
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

  const rows = useMemo(
    () => (q.data ?? []).filter((k) => (search.state ? keyState(k) === search.state : true) && matches(k, search.q ?? '')),
    [q.data, search.state, search.q],
  );

  const columns = useMemo(
    () => [
      col.accessor('name', { header: 'Name' }),
      col.accessor('prefix', { header: 'Key', meta: { help: 'apikey.prefix' }, cell: (c) => <span className="font-mono text-xs">cf_{c.getValue()}_…</span> }),
      col.accessor('scopes', {
        header: 'Permissions',
        cell: (c) => (
          <span className="flex flex-wrap gap-1">
            {c.getValue().map((s) => (
              <Badge key={s} variant="secondary" className="font-mono">
                {s}
              </Badge>
            ))}
          </span>
        ),
      }),
      col.accessor('orgId', { header: 'Scope', cell: (c) => scopeLabel(me, c.getValue()) }),
      col.accessor('createdByName', { header: 'Created by' }),
      col.accessor('expiresAt', { header: 'Expires', cell: (c) => (c.getValue() ? fmtDate(c.getValue()!) : 'Never') }),
      col.accessor('lastUsedAt', { header: 'Last used', cell: (c) => (c.getValue() ? fmtDateTime(c.getValue()!) : '–') }),
      col.display({
        id: 'state',
        header: 'Status',
        meta: { help: 'apikey.status' },
        cell: ({ row }) => {
          const s = STATE[keyState(row.original)];
          return <ToneChip tone={s.tone} icon={s.icon} label={s.label} />;
        },
      }),
      col.display({
        id: 'actions',
        header: '',
        cell: ({ row }) =>
          keyState(row.original) === 'active' &&
          can(me, 'apikeys:write', row.original.orgId) && (
            <Button
              variant="ghost"
              size="sm"
              aria-label={`Revoke ${row.original.name}`}
              onClick={(e) => {
                e.stopPropagation();
                setRevoking(row.original);
              }}
            >
              Revoke
            </Button>
          ),
      }),
    ],
    [me],
  );

  const add = canAnywhere(me, 'apikeys:write') && (
    <Button onClick={() => setCreating(true)}>
      <Plus className="size-4" aria-hidden />
      New API key
    </Button>
  );

  return (
    <div className="grid gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <SegmentedControl<'all' | 'active' | 'expired' | 'revoked'>
          aria-label="State filter"
          value={search.state ?? 'all'}
          onChange={(v) => void navigate({ search: (prev) => ({ ...prev, state: v === 'all' ? undefined : v }), replace: true })}
          options={[
            { value: 'all', label: 'All' },
            { value: 'active', label: 'Active' },
            { value: 'expired', label: 'Expired' },
            { value: 'revoked', label: 'Revoked' },
          ]}
        />
        <div className="ml-auto">{add}</div>
      </div>
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative w-72">
          <Search className="absolute left-2 top-2.5 size-4 text-ink-muted" aria-hidden />
          <Input aria-label="Search API keys" className="pl-8" placeholder="deploy" value={text} onChange={(e) => setText(e.target.value)} />
        </div>
        <SavedViews list="apikeys" current={{ q: search.q, state: search.state }} onApply={(s) => void navigate({ search: (prev) => ({ ...prev, ...s }) })} />
      </div>
      {q.isError ? (
        <ErrorState message={`Couldn't load API keys. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />
      ) : q.data && q.data.length === 0 ? (
        <EmptyState message="No API keys yet.">{add}</EmptyState>
      ) : q.data && rows.length === 0 ? (
        <EmptyState message="No API keys match this filter.">
          <Button
            variant="outline"
            onClick={() => {
              setText('');
              void navigate({ search: (prev) => ({ ...prev, q: undefined, state: undefined }), replace: true });
            }}
          >
            Clear filters
          </Button>
        </EmptyState>
      ) : isMdUp ? (
        <DataTable ariaLabel="API keys" data={rows} columns={columns} getRowId={(k) => k.id} skeletonRows={q.isPending ? 3 : undefined} />
      ) : q.isPending ? (
        <div className="grid gap-2">
          {Array.from({ length: 3 }).map((_, i) => (
            <KeyCardSkeleton key={i} />
          ))}
        </div>
      ) : (
        <div className="grid gap-2">
          {rows.map((k) => (
            <KeyCard key={k.id} k={k} canWrite={can(me, 'apikeys:write', k.orgId)} onRevoke={() => setRevoking(k)} />
          ))}
        </div>
      )}
      <ApiKeySheet open={creating} onOpenChange={setCreating} onCreated={setCreated} />
      <OneTimeSecretDialog token={created?.token ?? null} name={created?.apiKey.name ?? ''} onDone={() => setCreated(null)} />
      <ConfirmDestructive
        open={revoking !== null}
        onOpenChange={(o) => !o && setRevoking(null)}
        title={`Revoke ${revoking?.name ?? ''}`}
        consequence="Anything using this key is refused from its next request."
        confirmText={revoking?.name ?? ''}
        actionLabel="Revoke"
        onConfirm={() => revoke.mutateAsync(revoking!.id)}
      />
    </div>
  );
}
