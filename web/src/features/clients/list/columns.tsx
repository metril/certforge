import { createColumnHelper } from '@tanstack/react-table';
import { plural } from '@/api/queries/certificates';
import type { Client } from '@/api/types';
import { ConnectionDot } from '@/components/ConnectionDot';
import { PrimaryCell } from '@/components/PrimaryCell';
import { ToneChip } from '@/components/StatusChip';
import { CLIENT_STATUS_META } from '@/lib/clientStatus';
import { fmtDateTime, relTime } from '@/lib/time';

const col = createColumnHelper<Client>();
/** Muted second line of the Name cell (also the mobile card's): hostname,
 * site, agent version, grants, and drift/failed counts as plain text. */
export function clientMeta(c: Client, site?: string): string[] {
  return [
    c.hostname,
    site && site !== '–' ? site : '',
    c.agentVersion ? `agent ${c.agentVersion}` : '',
    plural(c.grantCount, 'grant'),
    c.driftCount > 0 ? `${c.driftCount} drift` : '',
    c.failedCount > 0 ? `${c.failedCount} failed` : '',
  ].filter(Boolean) as string[];
}

const stickyCol = 'sticky left-0 z-10 bg-panel';

/** siteName in one org; orgName under All orgs (sites are per org). */
export function clientColumns({ slugOf, siteName, orgName }: { slugOf: (c: Client) => string; siteName?: (id: string | null) => string; orgName?: (c: Client) => string }) {
  return [
    col.accessor('name', {
      header: 'Name',
      meta: { sortKey: 'name', className: stickyCol },
      cell: ({ row }) => (
        <PrimaryCell
          primary={row.original.name}
          link={{ to: '/o/$org/clients/$id', params: { org: slugOf(row.original), id: row.original.id } }}
          meta={clientMeta(row.original, siteName?.(row.original.siteId))}
        />
      ),
    }),
    ...(orgName
      ? [
          col.display({
            id: 'org',
            header: 'Org',
            meta: { className: 'w-28' },
            cell: ({ row }: { row: { original: Client } }) => <span className="truncate">{orgName(row.original)}</span>,
          }),
        ]
      : []),
    col.accessor('status', {
      header: 'Status',
      meta: { sortKey: 'status', className: 'w-28' },
      cell: ({ getValue }) => {
        const m = CLIENT_STATUS_META[getValue()];
        return <ToneChip tone={m.tone} icon={m.icon} label={m.label} />;
      },
    }),
    col.display({
      id: 'connection',
      header: 'Connection',
      meta: { className: 'w-36' },
      cell: ({ row }) => <ConnectionDot client={row.original} />,
    }),
    col.accessor('lastSeen', {
      header: 'Last seen',
      meta: { sortKey: 'lastSeen', className: 'w-32' },
      cell: ({ getValue }) => {
        const v = getValue();
        return v ? (
          <time dateTime={v} title={fmtDateTime(v)} className="whitespace-nowrap">
            {relTime(v)}
          </time>
        ) : (
          <span className="text-ink-muted">Never</span>
        );
      },
    }),
  ];
}
