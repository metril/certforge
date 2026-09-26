import { Link } from '@tanstack/react-router';
import { CircleAlert, Clock } from 'lucide-react';
import type { Readiness } from '@/api/queries/health';
import type { AgentListener } from '@/api/types';
import { EXPIRING_DAYS } from '@/lib/status';
import { daysUntil, relDays } from '@/lib/time';
import { cn } from '@/lib/utils';

/** Shown only when something is wrong: a failing /readyz check, or the
 * agent listener certificate under 14 days (it renews itself at two thirds,
 * so this means renewal is failing). Silent otherwise. */
export function HealthStrip({ readiness, listener }: { readiness?: Readiness; listener?: AgentListener }) {
  const failing = readiness && !readiness.ok ? readiness.checks.filter((c) => !c.ok) : [];
  const notAfter = listener?.notAfter ?? null;
  const listenerDue = notAfter !== null && daysUntil(notAfter) < EXPIRING_DAYS;
  if (failing.length === 0 && !listenerDue) return null;
  return (
    <div
      role="alert"
      aria-label={failing.length ? 'Server not ready' : 'Server health'}
      className={cn('flex flex-wrap items-center gap-3 rounded-md border px-4 py-2 text-sm', failing.length ? 'border-failed' : 'border-expiring')}
    >
      {failing.length > 0 && (
        <>
          <CircleAlert className="size-4 text-failed" aria-hidden />
          <span className="font-semibold">Server not ready</span>
          {failing.map((c) => (
            <span key={c.name} className="font-mono text-xs">
              {c.name}
              {c.message ? `: ${c.message}` : ''}
            </span>
          ))}
        </>
      )}
      {listenerDue && (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <Clock className="size-4 text-expiring" aria-hidden />
          Agent listener certificate expires {relDays(notAfter)}
          <Link to="/settings/$section" params={{ section: 'agents' }} className="text-primary underline-offset-2 hover:underline">
            Settings → Agents
          </Link>
        </span>
      )}
    </div>
  );
}
