import { Link } from '@tanstack/react-router';
import { CircleMinus, KeyRound, Plus, ShieldOff } from 'lucide-react';
import type { ImportItem, ImportSource } from '@/api/types';
import { columnHelper, DataTable } from '@/components/DataTable';
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
  return item.action === 'create' ? <ToneChip tone="valid" icon={Plus} label="Create" /> : <ToneChip tone="neutral" icon={CircleMinus} label="Skip" />;
}

function NameCell({ item, orgSlug }: { item: ImportItem; orgSlug: string }) {
  if (item.certificateId) {
    return (
      <Link
        to="/o/$org/certificates/$id/$tab"
        params={{ org: orgSlug, id: item.certificateId, tab: 'overview' }}
        className="block truncate font-mono text-xs font-semibold hover:underline"
      >
        {item.name}
      </Link>
    );
  }
  return <span className="block truncate font-mono text-xs">{item.name}</span>;
}

const col = columnHelper<Row>();

// Task 10 fix: every text cell needs `block` on its `truncate` span (an
// inline element's overflow-hidden doesn't clip against the table's own
// `table-fixed` column width, so a long acme.sh/certbot name overflowed
// into the next column instead of ellipsizing — caught by Playwright
// against a real browser, not jsdom, the same class of bug the CSP
// validator fix (3B) also only surfaced in a real browser) plus a
// `meta.className` width on every column so `table-fixed` has something
// to divide, the same convention `certColumns` (the certificates list)
// already uses.
function columns(orgSlug: string) {
  return [
    col.accessor('name', {
      header: 'Name',
      meta: { className: 'w-36' },
      cell: ({ row }) => <NameCell item={row.original} orgSlug={orgSlug} />,
    }),
    col.accessor('names', {
      header: 'Names',
      meta: { className: 'w-36' },
      cell: ({ getValue }) => (
        <span className="block truncate font-mono text-xs" title={getValue().join(', ')}>
          {namesSummary(getValue())}
        </span>
      ),
    }),
    col.accessor('notAfter', {
      header: 'Expires',
      meta: { className: 'w-28' },
      cell: ({ getValue }) => (
        <span className={cn('whitespace-nowrap text-xs', daysUntil(getValue()) < EXPIRING_SOON_DAYS && 'text-expiring')}>{fmtDate(getValue())}</span>
      ),
    }),
    col.accessor('issuer', {
      header: 'Issuer',
      meta: { className: 'w-32' },
      cell: ({ getValue }) => (
        <span className="block max-w-32 truncate text-xs" title={getValue()}>
          {getValue()}
        </span>
      ),
    }),
    col.accessor('hasKey', {
      header: 'Key',
      meta: { help: 'import.hasKey', className: 'w-24' },
      cell: ({ getValue }) => (getValue() ? <ToneChip tone="valid" icon={KeyRound} label="Key" /> : <ToneChip tone="neutral" icon={ShieldOff} label="No key" />),
    }),
    col.accessor('source', { header: 'Source', meta: { className: 'w-20' }, cell: ({ getValue }) => SOURCE_LABEL[getValue()] }),
    col.display({
      id: 'action',
      header: 'Action',
      meta: { help: 'import.action' },
      cell: ({ row }) => (
        <div className="flex flex-wrap items-center gap-2">
          <ActionChip item={row.original} />
          <span className="truncate text-xs text-ink-muted" title={row.original.reason}>
            {row.original.reason}
          </span>
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
        <dd className="truncate" title={item.reason}>
          {item.reason}
        </dd>
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
