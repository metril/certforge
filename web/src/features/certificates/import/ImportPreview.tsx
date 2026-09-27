import { Link } from '@tanstack/react-router';
import { createColumnHelper } from '@tanstack/react-table';
import { CircleMinus, Key, Plus } from 'lucide-react';
import type { ImportItem, ImportSource } from '@/api/types';
import { DataTable } from '@/components/DataTable';
import { ToneChip } from '@/components/StatusChip';
import { daysUntil, fmtDate } from '@/lib/time';
import { cn } from '@/lib/utils';

const SOURCE_LABEL: Record<ImportSource, string> = { acmesh: 'acme.sh', certbot: 'certbot' };
// Expiring under 30 d, distinct from EXPIRING_DAYS (14, an issued
// certificate's own renewal-window threshold): an imported certificate has
// no CertForge renewal history yet, so the preview flags it earlier.
const EXPIRING_SOON_DAYS = 30;

type Row = ImportItem & { _key: string };

function namesSummary(names: string[]): string {
  const [first, ...rest] = names;
  if (!first) return '–';
  return rest.length > 0 ? `${first} +${rest.length}` : first;
}

function ActionChip({ item }: { item: ImportItem }) {
  if (item.action === 'create') {
    return (
      <span className="inline-flex h-6 items-center gap-1 whitespace-nowrap rounded-sm border border-primary/40 bg-primary/12 px-2 text-xs font-semibold text-ink">
        <Plus className="size-3.5 text-primary" aria-hidden />
        Create
      </span>
    );
  }
  return <ToneChip tone="neutral" icon={CircleMinus} label="Skip" />;
}

function NameCell({ item, orgSlug }: { item: ImportItem; orgSlug: string }) {
  if (item.certificateId) {
    return (
      <Link
        to="/o/$org/certificates/$id/$tab"
        params={{ org: orgSlug, id: item.certificateId, tab: 'overview' }}
        className="truncate font-mono text-xs font-semibold hover:underline"
      >
        {item.name}
      </Link>
    );
  }
  return <span className="truncate font-mono text-xs">{item.name}</span>;
}

const col = createColumnHelper<Row>();

function columns(orgSlug: string) {
  return [
    col.accessor('name', { header: 'Name', cell: ({ row }) => <NameCell item={row.original} orgSlug={orgSlug} /> }),
    col.accessor('names', {
      header: 'Names',
      cell: ({ getValue }) => (
        <span className="truncate font-mono text-xs" title={getValue().join(', ')}>
          {namesSummary(getValue())}
        </span>
      ),
    }),
    col.accessor('notAfter', {
      header: 'Expires',
      cell: ({ getValue }) => (
        <span className={cn('whitespace-nowrap text-xs', daysUntil(getValue()) < EXPIRING_SOON_DAYS && 'text-expiring')}>{fmtDate(getValue())}</span>
      ),
    }),
    col.accessor('issuer', {
      header: 'Issuer',
      cell: ({ getValue }) => (
        <span className="block max-w-32 truncate text-xs" title={getValue()}>
          {getValue()}
        </span>
      ),
    }),
    col.accessor('hasKey', {
      header: 'Key',
      meta: { help: 'import.hasKey' },
      cell: ({ getValue }) => (getValue() ? <ToneChip tone="valid" icon={Key} label="Key" /> : <ToneChip tone="neutral" icon={Key} label="No key" />),
    }),
    col.accessor('source', { header: 'Source', cell: ({ getValue }) => SOURCE_LABEL[getValue()] }),
    col.display({
      id: 'action',
      header: 'Action',
      meta: { help: 'import.action' },
      cell: ({ row }) => (
        <div className="flex flex-wrap items-center gap-2">
          <ActionChip item={row.original} />
          <span className="truncate text-xs text-ink-muted">{row.original.reason}</span>
        </div>
      ),
    }),
  ];
}

// D1: card rows below `md`, no horizontal overflow at 375px.
function ImportCard({ item, orgSlug }: { item: ImportItem; orgSlug: string }) {
  return (
    <div className="grid gap-1.5 rounded-md border border-border bg-panel p-3">
      <div className="flex items-center justify-between gap-2">
        <NameCell item={item} orgSlug={orgSlug} />
        <ActionChip item={item} />
      </div>
      <dl className="grid grid-cols-[5rem_1fr] gap-x-2 gap-y-1 text-xs text-ink-muted">
        <dt>Names</dt>
        <dd className="truncate" title={item.names.join(', ')}>
          {namesSummary(item.names)}
        </dd>
        <dt>Expires</dt>
        <dd className={cn(daysUntil(item.notAfter) < EXPIRING_SOON_DAYS && 'text-expiring')}>{fmtDate(item.notAfter)}</dd>
        <dt>Issuer</dt>
        <dd className="truncate">{item.issuer}</dd>
        <dt>Key</dt>
        <dd>{item.hasKey ? 'Key' : 'No key'}</dd>
        <dt>Source</dt>
        <dd>{SOURCE_LABEL[item.source]}</dd>
        <dt>Reason</dt>
        <dd className="truncate">{item.reason}</dd>
      </dl>
    </div>
  );
}

/** The dry-run/real-run result table (Task 6): one row per archive entry,
 * whether it was created or skipped and why. Below `md` each row becomes a
 * card instead of scrolling the table horizontally (D1). */
export function ImportPreview({ items, orgSlug, isMdUp }: { items: ImportItem[]; orgSlug: string; isMdUp: boolean }) {
  const rows: Row[] = items.map((it, i) => ({ ...it, _key: `${it.name}-${i}` }));
  if (!isMdUp) {
    return (
      <div className="grid gap-2">
        {rows.map((r) => (
          <ImportCard key={r._key} item={r} orgSlug={orgSlug} />
        ))}
      </div>
    );
  }
  return <DataTable ariaLabel="Import preview" data={rows} columns={columns(orgSlug)} getRowId={(r) => r._key} />;
}
