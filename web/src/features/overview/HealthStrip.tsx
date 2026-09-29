import { Link } from '@tanstack/react-router';
import { CircleAlert, Clock, TriangleAlert } from 'lucide-react';
import type { Readiness } from '@/api/queries/health';
import type { AgentListener } from '@/api/types';
import type { SectionSlug } from '@/features/settings/sections';
import { EXPIRING_DAYS } from '@/lib/status';
import { daysUntil, relDays } from '@/lib/time';
import { cn } from '@/lib/utils';

// A degraded check's fix lives on its own settings section (Deviations,
// "HealthStrip"): backup goes to Settings -> Backup and keys, everything
// else (today, only vault) stays on Integrations.
const DEGRADED_LINK: Record<string, { section: SectionSlug; label: string }> = {
  backup: { section: 'backup', label: 'Backup and keys' },
};
const DEFAULT_DEGRADED_LINK: { section: SectionSlug; label: string } = { section: 'integrations', label: 'Integrations' };

/** Shown only when something is wrong: a failing /readyz check, a degraded
 * one (Vault reachable but not fully healthy — 5a-facts.md's checks.vault),
 * or the agent listener certificate under 14 days (it renews itself at two
 * thirds, so this means renewal is failing). Silent otherwise. */
export function HealthStrip({ readiness, listener }: { readiness?: Readiness; listener?: AgentListener }) {
  // A degraded check is never a failure (Deviations R7/preflight ruling):
  // the server can still be ready while it warns about a degraded section.
  const failing = readiness && !readiness.ok ? readiness.checks.filter((c) => !c.ok && c.status !== 'degraded') : [];
  const degraded = readiness ? readiness.checks.filter((c) => c.status === 'degraded') : [];
  const notAfter = listener?.notAfter ?? null;
  const dueIn = notAfter !== null ? daysUntil(notAfter) : null;
  const listenerDue = dueIn !== null && dueIn < EXPIRING_DAYS;
  if (failing.length === 0 && degraded.length === 0 && !listenerDue) return null;
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
      {degraded.map((c) => {
        const link = DEGRADED_LINK[c.name] ?? DEFAULT_DEGRADED_LINK;
        return (
          <span key={c.name} className="inline-flex flex-wrap items-center gap-1.5">
            <TriangleAlert className="size-4 text-expiring" aria-hidden />
            <span className="font-mono text-xs">{c.name}: degraded</span>
            <Link to="/settings/$section" params={{ section: link.section }} className="text-primary underline-offset-2 hover:underline">
              {link.label}
            </Link>
          </span>
        );
      })}
      {listenerDue && (
        <span className="inline-flex flex-wrap items-center gap-1.5">
          <Clock className="size-4 text-expiring" aria-hidden />
          Agent listener certificate {dueIn !== null && dueIn <= 0 ? 'expired' : 'expires'} {relDays(notAfter!)}
          <Link to="/settings/$section" params={{ section: 'agents' }} className="text-primary underline-offset-2 hover:underline">
            Settings → Agents
          </Link>
        </span>
      )}
    </div>
  );
}
