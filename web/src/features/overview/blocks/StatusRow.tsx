import { Link } from '@tanstack/react-router';
import { CircleAlert, CircleCheck, CircleX, Hourglass } from 'lucide-react';
import type { Readiness } from '@/api/queries/health';
import type { AgentListener } from '@/api/types';
import { HealthStrip } from '../HealthStrip';

const TILES = [
  { status: 'active', label: 'Active', icon: CircleCheck, cls: 'text-valid' },
  { status: 'pending', label: 'Pending', icon: Hourglass, cls: 'text-pending' },
  { status: 'failed', label: 'Failed', icon: CircleAlert, cls: 'text-failed' },
  { status: 'expired', label: 'Expired', icon: CircleX, cls: 'text-expired' },
] as const;

/** Block 1: the status tiles (each a certificates-list filter) and, only when
 * something is wrong, the health strip, in one wrapping row. */
export function StatusRow({
  counts,
  orgSlug,
  readiness,
  listener,
}: {
  counts: Record<(typeof TILES)[number]['status'], number>;
  orgSlug: string;
  readiness?: Readiness;
  listener?: AgentListener;
}) {
  return (
    <div className="flex flex-wrap items-center gap-2">
      <nav aria-label="Filter certificates by status" className="flex flex-wrap gap-2">
        {TILES.map((t) => (
          <Link
            key={t.status}
            to="/o/$org/certificates"
            params={{ org: orgSlug }}
            search={{ status: t.status }}
            aria-label={`${counts[t.status]} ${t.label}`}
            className="inline-flex h-9 items-center gap-2 rounded-md border border-border px-3 text-sm hover:bg-subtle"
          >
            <t.icon className={`size-4 ${t.cls}`} aria-hidden />
            <span className="font-semibold tabular-nums">{counts[t.status]}</span>
            {t.label}
          </Link>
        ))}
      </nav>
      <HealthStrip readiness={readiness} listener={listener} />
    </div>
  );
}
