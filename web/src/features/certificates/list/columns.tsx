import { Link } from '@tanstack/react-router';
import { createColumnHelper } from '@tanstack/react-table';
import type { Certificate } from '@/api/types';
import { StatusChip } from '@/components/StatusChip';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { CertValidity } from '@/components/ValidityBar';
import { relDays } from '@/lib/time';
import { cn } from '@/lib/utils';

const col = createColumnHelper<Certificate>();

// Matches the CasPage/CredentialsPage convention: the leading column stays
// in view while a narrow table scrolls horizontally.
const stickyCol = 'sticky left-0 z-10 bg-panel';

export function certColumns(
  org: string | ((c: Certificate) => string),
  caName: (id: string | undefined) => string | undefined,
  orgName?: (c: Certificate) => string,
) {
  const slugOf = typeof org === 'string' ? () => org : org;
  return [
    col.accessor('name', {
      header: 'Name',
      meta: { sortKey: 'name', className: cn('w-44', stickyCol) },
      cell: ({ row }) => (
        <div className="grid min-w-0">
          <Link
            to="/o/$org/certificates/$id/$tab"
            params={{ org: slugOf(row.original), id: row.original.id, tab: 'overview' }}
            onClick={(e) => e.stopPropagation()}
            className="truncate font-semibold hover:underline"
          >
            {row.original.name}
          </Link>
          <span className="truncate font-mono text-xs text-ink-muted">{row.original.commonName}</span>
        </div>
      ),
    }),
    ...(orgName
      ? [
          col.display({
            id: 'org',
            header: 'Org',
            meta: { className: 'w-28' },
            cell: ({ row }) => orgName(row.original),
          }),
        ]
      : []),
    // Controller ruling (design.md screen inventory, "certificates" row):
    // the names column is the SANs, truncated with a tooltip listing every
    // name in full — not just a count.
    col.accessor('sans', {
      header: 'Names',
      meta: { help: 'cert.namesColumn', className: 'w-40' },
      cell: ({ getValue }) => {
        const sans = getValue();
        if (sans.length === 0) return <span className="text-ink-muted">–</span>;
        return (
          <Tooltip>
            <TooltipTrigger asChild>
              <span tabIndex={0} className="block truncate font-mono text-xs">
                {sans.join(', ')}
              </span>
            </TooltipTrigger>
            <TooltipContent side="top" className="max-w-72 font-mono text-xs break-all">
              {sans.join(', ')}
            </TooltipContent>
          </Tooltip>
        );
      },
    }),
    col.accessor('status', { header: 'Status', meta: { help: 'status.column' }, cell: ({ getValue }) => <StatusChip status={getValue()} /> }),
    col.display({
      id: 'validity',
      header: 'Validity',
      meta: { sortKey: 'notAfter', help: 'cert.validity', className: 'w-60' },
      cell: ({ row }) => (
        <div className="flex items-center gap-2">
          <div className="w-32">
            <CertValidity cert={row.original} />
          </div>
          <span className="whitespace-nowrap text-xs tabular-nums text-ink-muted">
            {row.original.currentVersion ? relDays(row.original.currentVersion.notAfter) : '–'}
          </span>
        </div>
      ),
    }),
    col.display({
      id: 'ca',
      header: 'CA',
      cell: ({ row }) => caName(row.original.effective?.caId?.value ?? undefined) ?? '–',
    }),
    col.accessor('nextRenewAt', {
      header: 'Next renewal',
      meta: { sortKey: 'nextRenewAt', help: 'cert.nextRenew' },
      cell: ({ getValue }) => {
        const v = getValue();
        return v ? <span className="whitespace-nowrap">{relDays(v)}</span> : '–';
      },
    }),
    // design.md screen inventory lists a "grants" column for the
    // certificates list; grants (client × certificate assignments) are
    // Phase 3 work, so this is a placeholder column per the controller
    // ruling ("grants (Phase 3, render '–')").
    col.display({ id: 'grants', header: 'Grants', cell: () => '–' }),
  ];
}
