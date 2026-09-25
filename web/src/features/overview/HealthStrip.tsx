import { CircleAlert } from 'lucide-react';
import type { Readiness } from '@/api/queries/health';

/** Shown only when /readyz reports a failing check; silent (renders
 * nothing) once the server is ready, so a healthy overview has no banner. */
export function HealthStrip({ readiness }: { readiness?: Readiness }) {
  if (!readiness || readiness.ok) return null;
  const failing = readiness.checks.filter((c) => !c.ok);
  return (
    <div role="alert" aria-label="Server not ready" className="flex flex-wrap items-center gap-3 rounded-md border border-failed px-4 py-2 text-sm">
      <CircleAlert className="size-4 text-failed" aria-hidden />
      <span className="font-semibold">Server not ready</span>
      {failing.map((c) => (
        <span key={c.name} className="font-mono text-xs">
          {c.name}
          {c.message ? `: ${c.message}` : ''}
        </span>
      ))}
    </div>
  );
}
