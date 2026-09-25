import { createColumnHelper } from '@tanstack/react-table';
import type { AuditEvent } from '@/api/types';
import { fmtDateTime } from '@/lib/time';

const col = createColumnHelper<AuditEvent>();

export function auditColumns(orgName?: (id: string | null) => string) {
  return [
    col.accessor('ts', { header: 'Time', meta: { className: 'w-52 pr-4' }, cell: (c) => <span className="font-mono text-xs">{fmtDateTime(c.getValue())}</span> }),
    col.accessor('actorName', { header: 'Actor', meta: { help: 'audit.actor', className: 'w-40' }, cell: ({ row }) => <span className="truncate">{row.original.actorName || row.original.actorType}</span> }),
    col.accessor('action', { header: 'Action', meta: { className: 'w-56' }, cell: (c) => <span className="font-mono text-xs">{c.getValue()}</span> }),
    col.display({
      id: 'resource',
      header: 'Resource',
      cell: ({ row }) => (
        <span className="grid min-w-0">
          <span className="truncate">{row.original.resourceType}</span>
          <span className="truncate font-mono text-xs text-ink-muted">{row.original.resourceId}</span>
        </span>
      ),
    }),
    ...(orgName ? [col.accessor('orgId', { header: 'Org', meta: { className: 'w-28' }, cell: (c) => orgName(c.getValue()) })] : []),
    col.accessor('ip', { header: 'IP', meta: { help: 'audit.ip', className: 'w-32' }, cell: (c) => <span className="font-mono text-xs">{c.getValue() || '–'}</span> }),
  ];
}
