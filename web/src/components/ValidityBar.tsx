import type { Certificate } from '@/api/types';
import { validityTone, type Tone } from '@/lib/status';
import { DAY, fmtDate, relDays } from '@/lib/time';
import { cn } from '@/lib/utils';

type Span = { notBefore: string; notAfter: string };
export type ValidityProps = Span & {
  renewAt?: string | null;
  ghost?: Span | null;
  tone: Tone;
  now?: number;
  size?: 'compact' | 'full';
  className?: string;
};

const clamp = (v: number, lo = 0, hi = 100) => Math.min(hi, Math.max(lo, v));

/** Percent positions of now/end/window/ghost along the notBefore..notAfter
 * lifetime (extended to cover a ghost successor's own notAfter, if later). */
export function validityGeometry({ notBefore, notAfter, renewAt, ghost, now }: Span & { renewAt?: string | null; ghost?: Span | null; now: number }) {
  const start = Date.parse(notBefore);
  const end = Date.parse(notAfter);
  const domainEnd = ghost ? Math.max(end, Date.parse(ghost.notAfter)) : end;
  const span = Math.max(domainEnd - start, 1);
  const pct = (t: number) => clamp(((t - start) / span) * 100);
  return {
    end: pct(end),
    now: pct(now),
    elapsed: Math.min(pct(now), pct(end)),
    window: renewAt ? { from: pct(Date.parse(renewAt)), to: pct(end) } : null,
    ghost: ghost ? { from: pct(Date.parse(ghost.notBefore)), to: pct(Date.parse(ghost.notAfter)) } : null,
    lifetimeDays: Math.round((end - start) / DAY),
  };
}

function renewPhrase(renewAt: string | null | undefined, now: number): string | null {
  if (!renewAt) return null;
  return Date.parse(renewAt) <= now ? 'renewal due' : `renews ${relDays(renewAt, now)}`;
}

/** The bar's text alternative, e.g. "Valid 12 Sep 2026 to 12 Nov 2026, expires in 23 d, renews in 9 d". */
export function validityLabel(p: ValidityProps, now: number): string {
  const expired = Date.parse(p.notAfter) <= now;
  const parts = [`Valid ${fmtDate(p.notBefore)} to ${fmtDate(p.notAfter)}`, expired ? `expired ${relDays(p.notAfter, now)}` : `expires ${relDays(p.notAfter, now)}`];
  const renew = renewPhrase(p.renewAt, now);
  if (renew && !expired) parts.push(renew);
  return parts.join(', ');
}

const FILL: Record<Tone, string> = {
  valid: 'bg-valid',
  expiring: 'bg-expiring',
  expired: 'bg-expired',
  failed: 'bg-failed',
  pending: 'bg-pending',
  drift: 'bg-drift',
  neutral: 'bg-ink-muted',
};

/** The signature validity bar: a thin track from notBefore to notAfter, the
 * renewal window hatched, a "now" notch, and (once a successor exists) a
 * dashed ghost segment for its own span. Pure and deterministic: pass `now`
 * so tests and screenshots don't depend on the wall clock. */
export function ValidityBar(p: ValidityProps) {
  const now = p.now ?? Date.now();
  const g = validityGeometry({ ...p, now });
  const full = p.size === 'full';
  const fill = FILL[p.tone];
  const renew = renewPhrase(p.renewAt, now);
  const bar = (
    <div role="img" aria-label={validityLabel(p, now)} className={cn('relative w-full', full ? 'my-1.5' : 'my-1', !full && p.className)}>
      <div className={cn('relative w-full bg-subtle', full ? 'h-2.5' : 'h-1.5')}>
        <div className={cn('absolute inset-y-0 left-0 opacity-25', fill)} style={{ width: `${g.elapsed}%` }} />
        <div className={cn('absolute inset-y-0', fill)} style={{ left: `${g.elapsed}%`, width: `${Math.max(g.end - g.elapsed, 0)}%` }} />
        {g.window && g.window.to > g.window.from && (
          <div className="cf-hatch absolute inset-y-0 opacity-80" style={{ left: `${g.window.from}%`, width: `${g.window.to - g.window.from}%` }} />
        )}
        {g.ghost && (
          <div className="absolute inset-y-0 border border-dashed border-pending" style={{ left: `${g.ghost.from}%`, width: `${g.ghost.to - g.ghost.from}%` }} />
        )}
        <div className="absolute -inset-y-1 w-0.5 -translate-x-1/2 bg-ink" style={{ left: `${g.now}%` }} />
      </div>
    </div>
  );
  if (!full) return bar;
  return (
    <div className={cn('grid', p.className)}>
      {renew && g.window && (
        <div className="relative h-4 text-xs text-ink-muted" aria-hidden>
          <span className="absolute -translate-x-1/2 whitespace-nowrap" style={{ left: `${clamp(g.window.from, 8, 92)}%` }}>
            {renew}
          </span>
        </div>
      )}
      {bar}
      <div className="flex justify-between gap-4 text-xs text-ink-muted" aria-hidden>
        <span>Issued {fmtDate(p.notBefore)}</span>
        <span>
          Expires {fmtDate(p.notAfter)} ({relDays(p.notAfter, now)})
        </span>
      </div>
    </div>
  );
}

/** The bar for a certificate, or nothing when it has never been issued. */
export function CertValidity({ cert, size = 'compact', now, className }: { cert: Certificate; size?: 'compact' | 'full'; now?: number; className?: string }) {
  const v = cert.currentVersion;
  if (!v) return null;
  return (
    <ValidityBar notBefore={v.notBefore} notAfter={v.notAfter} renewAt={cert.nextRenewAt} tone={validityTone(cert, now)} now={now} size={size} className={className} />
  );
}
