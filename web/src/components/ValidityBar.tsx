import type { AriWindow, Certificate } from '@/api/types';
import { validityTone, type Tone } from '@/lib/status';
import { DAY, fmtDate, relDays, relTime } from '@/lib/time';
import { cn } from '@/lib/utils';
import { HelpTip } from './HelpTip';

type Span = { notBefore: string; notAfter: string };
export type ValidityProps = Span & {
  renewAt?: string | null;
  ghost?: Span | null;
  ari?: AriWindow | null;
  tone: Tone;
  now?: number;
  size?: 'compact' | 'full';
  className?: string;
};

// Fix round 1 (#6): an invalid/unparseable timestamp makes every ratio below
// NaN; treat that as 0% instead of letting `width: NaN%` reach the DOM.
const clamp = (v: number, lo = 0, hi = 100) => (Number.isFinite(v) ? Math.min(hi, Math.max(lo, v)) : 0);

// Fix round 1 (#4): a ghost successor is only real when it's a proper span
// (notAfter after notBefore) and it isn't just the current version's own
// span handed back unchanged.
function ghostValid(current: Span, ghost: Span): boolean {
  const gs = Date.parse(ghost.notBefore);
  const ge = Date.parse(ghost.notAfter);
  if (!(ge > gs)) return false;
  return !(gs === Date.parse(current.notBefore) && ge === Date.parse(current.notAfter));
}

/** Percent positions of now/end/window/ghost along the notBefore..notAfter
 * lifetime (extended to cover a ghost successor's own notAfter, if later). */
export function validityGeometry({
  notBefore,
  notAfter,
  renewAt,
  ghost,
  ari,
  now,
}: Span & { renewAt?: string | null; ghost?: Span | null; ari?: AriWindow | null; now: number }) {
  const start = Date.parse(notBefore);
  const end = Date.parse(notAfter);
  const current = { notBefore, notAfter };
  const domainEnd = ghost && ghostValid(current, ghost) ? Math.max(end, Date.parse(ghost.notAfter)) : end;
  const span = Math.max(domainEnd - start, 1);
  const pct = (t: number) => clamp(((t - start) / span) * 100);
  // Task 7: the ARI window is only drawn when it overlaps the lifetime at
  // all — an ARI window the CA already moved past (or hasn't reached yet
  // relative to a stale fixture) has nothing sensible to clamp onto.
  const ariStart = ari ? Date.parse(ari.start) : NaN;
  const ariEnd = ari ? Date.parse(ari.end) : NaN;
  const ariOutside = !ari || !Number.isFinite(ariStart) || !Number.isFinite(ariEnd) || ariEnd < start || ariStart > domainEnd;
  return {
    end: pct(end),
    now: pct(now),
    elapsed: Math.min(pct(now), pct(end)),
    window: renewAt ? { from: pct(Date.parse(renewAt)), to: pct(end) } : null,
    ghost: ghost && ghostValid(current, ghost) ? { from: pct(Date.parse(ghost.notBefore)), to: pct(Date.parse(ghost.notAfter)) } : null,
    ari: ariOutside ? null : { from: pct(ariStart), to: pct(ariEnd) },
    lifetimeDays: Math.round((end - start) / DAY),
  };
}

function renewPhrase(renewAt: string | null | undefined, now: number): string | null {
  if (!renewAt) return null;
  return Date.parse(renewAt) <= now ? 'renewal due' : `renews ${relDays(renewAt, now)}`;
}

/** The bar's text alternative, e.g. "Valid 12 Sep 2026 to 12 Nov 2026, expires in 23 d, renews in 9 d".
 * `ariVisible` is the *clamped* geometry (`validityGeometry`'s own `ari`),
 * not just whether `p.ari` was passed — fix round 1 (review, Minor): a
 * window entirely outside the lifetime is drawn nowhere on the bar and must
 * not be named in the accessible text either. */
export function validityLabel(p: ValidityProps, now: number, ariVisible: boolean): string {
  const expired = Date.parse(p.notAfter) <= now;
  const parts = [`Valid ${fmtDate(p.notBefore)} to ${fmtDate(p.notAfter)}`, expired ? `expired ${relDays(p.notAfter, now)}` : `expires ${relDays(p.notAfter, now)}`];
  const renew = renewPhrase(p.renewAt, now);
  if (renew && !expired) parts.push(renew);
  // Fix round 1 (#4): name the ghost successor in the accessible text, not
  // just as a visual dashed segment.
  if (p.ghost && ghostValid({ notBefore: p.notBefore, notAfter: p.notAfter }, p.ghost)) {
    parts.push(`next version until ${fmtDate(p.ghost.notAfter)}`);
  }
  if (ariVisible && p.ari) parts.push(`ARI window ${fmtDate(p.ari.start)} to ${fmtDate(p.ari.end)}`);
  return parts.join(', ');
}

function ariPhrase(ari: AriWindow, now: number): string {
  return `ARI window ${fmtDate(ari.start)} to ${fmtDate(ari.end)}, checked ${relTime(ari.checkedAt, now)}`;
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
    <div role="img" aria-label={validityLabel(p, now, !!g.ari)} className={cn('relative w-full', full ? 'my-1.5' : 'my-1', !full && p.className)}>
      {g.ari && <div className="absolute -top-1 h-0.5 bg-primary" style={{ left: `${g.ari.from}%`, width: `${Math.max(g.ari.to - g.ari.from, 0)}%` }} />}
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
          {/* Fix round 1 (#3): centering the label on `from` with -translate-x-1/2
              lets its right half overflow the track once `from` is close to
              100% (e.g. a narrow renewal window right before expiry). Past
              ~80% anchor to the track's own right edge instead, so a 343px
              track on a 375px screen never scrolls horizontally. */}
          {g.window.from > 80 ? (
            <span className="absolute right-0 whitespace-nowrap">{renew}</span>
          ) : (
            <span className="absolute -translate-x-1/2 whitespace-nowrap" style={{ left: `${clamp(g.window.from, 8, 92)}%` }}>
              {renew}
            </span>
          )}
        </div>
      )}
      {bar}
      <div className="flex justify-between gap-4 text-xs text-ink-muted" aria-hidden>
        <span>Issued {fmtDate(p.notBefore)}</span>
        <span>
          Expires {fmtDate(p.notAfter)} ({relDays(p.notAfter, now)})
        </span>
      </div>
      {/* Pre-flight C2: sits outside both the role="img" bar above and the
          aria-hidden legend, so its HelpTip is reachable by keyboard/screen
          reader instead of being flattened out of the accessible tree.
          Keyed on `g.ari` (fix round 1, review Minor), not just `p.ari`:
          a window entirely outside the lifetime is drawn nowhere on the
          bar and gets no row either. No separate Tooltip here — the row's
          own visible text already states exactly what a tooltip would
          have repeated (fix round 1, review Minor). */}
      {g.ari && p.ari && (
        <div className="flex items-center gap-1.5 text-xs text-ink-muted">
          <span>{ariPhrase(p.ari, now)}</span>
          <HelpTip id="cert.ari" />
        </div>
      )}
    </div>
  );
}

/** The bar for a certificate, or nothing when it has never been issued. */
export function CertValidity({ cert, size = 'compact', now, className }: { cert: Certificate; size?: 'compact' | 'full'; now?: number; className?: string }) {
  const v = cert.currentVersion;
  if (!v) return null;
  return (
    <ValidityBar
      notBefore={v.notBefore}
      notAfter={v.notAfter}
      renewAt={cert.nextRenewAt}
      ari={cert.ariWindow}
      tone={validityTone(cert, now)}
      now={now}
      size={size}
      className={className}
    />
  );
}
