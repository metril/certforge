import { createColumnHelper } from '@tanstack/react-table';
import { Link } from '@tanstack/react-router';
import type { Client } from '@/api/types';
import { ConnectionDot } from '@/components/ConnectionDot';
import { DeploymentCounts } from '@/components/DeploymentChip';
import { ToneChip } from '@/components/StatusChip';
import { CLIENT_STATUS_META } from '@/lib/clientStatus';
import { fmtDateTime, relTime } from '@/lib/time';
import { cn } from '@/lib/utils';

const col = createColumnHelper<Client>();
const stickyCol = 'sticky left-0 z-10 bg-panel';

/** siteName in one org; orgName under All orgs (sites are per org). */
export function clientColumns({ slugOf, siteName, orgName }: { slugOf: (c: Client) => string; siteName?: (id: string | null) => string; orgName?: (c: Client) => string }) {
  return [
    col.accessor('name', {
      header: 'Name',
      meta: { sortKey: 'name', className: cn('w-48', stickyCol) },
      cell: ({ row }) => (
        <div className="grid min-w-0">
          <Link
            to="/o/$org/clients/$id"
            params={{ org: slugOf(row.original), id: row.original.id }}
            onClick={(e) => e.stopPropagation()}
            className="truncate font-semibold hover:underline"
          >
            {row.original.name}
          </Link>
          <span className="truncate font-mono text-xs text-ink-muted">{row.original.hostname || '–'}</span>
        </div>
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
      meta: { sortKey: 'status', help: 'client.status', className: 'w-28' },
      cell: ({ getValue }) => {
        const m = CLIENT_STATUS_META[getValue()];
        return <ToneChip tone={m.tone} icon={m.icon} label={m.label} />;
      },
    }),
    col.display({
      id: 'connection',
      header: 'Connection',
      meta: { help: 'client.connection', className: 'w-36' },
      cell: ({ row }) => <ConnectionDot client={row.original} />,
    }),
    ...(siteName
      ? [
          col.accessor('siteId', {
            header: 'Site',
            meta: { help: 'client.site', className: 'w-32' },
            cell: ({ getValue }: { getValue: () => string | null }) => <span className="truncate">{siteName(getValue())}</span>,
          }),
        ]
      : []),
    col.accessor('agentVersion', {
      header: 'Agent',
      meta: { help: 'client.agentVersion', className: 'w-28' },
      cell: ({ getValue }) => (getValue() ? <span className="font-mono text-xs">{getValue()}</span> : <span className="text-ink-muted">–</span>),
    }),
    col.accessor('grantCount', {
      header: 'Grants',
      meta: { help: 'client.grants', className: 'w-24' },
      cell: ({ getValue }) => <span className="tabular-nums">{getValue()}</span>,
    }),
    col.display({ id: 'drift', header: 'Drift', meta: { help: 'client.drift', className: 'w-40' }, cell: ({ row }) => <DeploymentCounts client={row.original} /> }),
    col.accessor('lastSeen', {
      header: 'Last seen',
      meta: { sortKey: 'lastSeen', help: 'client.lastSeen', className: 'w-32' },
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
