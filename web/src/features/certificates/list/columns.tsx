import { createColumnHelper } from '@tanstack/react-table';
import { plural } from '@/api/queries/certificates';
import type { Certificate } from '@/api/types';
import { PrimaryCell } from '@/components/PrimaryCell';
import { StatusChip } from '@/components/StatusChip';
import { CertValidity } from '@/components/ValidityBar';
import { relDays } from '@/lib/time';

const col = createColumnHelper<Certificate>();

// Matches the CasPage/CredentialsPage convention: the leading column stays
// in view while a narrow table scrolls horizontally.
const stickyCol = 'sticky left-0 z-10 bg-panel';

/** Muted second line of the Name cell: common name, CA, grants, then every
 * other name (the PrimaryCell tooltip shows the whole line). */
export function certMeta(c: Certificate, ca: string | undefined): string[] {
  const names = c.sans.filter((n) => n !== c.commonName).join(', ');
  return [c.commonName, ca, c.grantCount ? plural(c.grantCount, 'grant') : '', names].filter(Boolean) as string[];
}

export function certColumns(
  org: string | ((c: Certificate) => string),
  caName: (id: string | undefined) => string | undefined,
  orgName?: (c: Certificate) => string,
) {
  const slugOf = typeof org === 'string' ? () => org : org;
  return [
    col.accessor('name', {
      header: 'Name',
      meta: { sortKey: 'name', className: stickyCol },
      cell: ({ row }) => (
        <PrimaryCell
          primary={row.original.name}
          link={{ to: '/o/$org/certificates/$id/$tab', params: { org: slugOf(row.original), id: row.original.id, tab: 'overview' } }}
          meta={certMeta(row.original, caName(row.original.effective?.caId?.value ?? undefined))}
        />
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
    col.accessor('status', { header: 'Status', meta: { className: 'w-28' }, cell: ({ getValue }) => <StatusChip status={getValue()} /> }),
    col.display({
      id: 'validity',
      header: 'Validity',
      meta: { sortKey: 'notAfter', className: 'w-60', hint: 'cert.validity' },
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
    col.accessor('nextRenewAt', {
      header: 'Next renewal',
      meta: { sortKey: 'nextRenewAt', className: 'w-32', hint: 'cert.nextRenew' },
      cell: ({ getValue }) => {
        const v = getValue();
        return v ? <span className="whitespace-nowrap">{relDays(v)}</span> : '–';
      },
    }),
  ];
}
