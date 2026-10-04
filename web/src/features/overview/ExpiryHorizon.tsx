import { useRef, useState } from 'react';
import type { CertBrief } from '@/api/types';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { validityTone, type Tone } from '@/lib/status';
import { DAY, relDays } from '@/lib/time';

export const HORIZON_DAYS = 90;
const W = 1000;
const TONE_VAR: Record<Tone, string> = {
  valid: '--cf-valid',
  expiring: '--cf-expiring',
  expired: '--cf-expired',
  failed: '--cf-failed',
  pending: '--cf-pending',
  drift: '--cf-drift',
  neutral: '--cf-ink-muted',
};

/** Keyboard-reachable alternative to the pointer brush: "expiring within N days". */
const PRESETS = [7, 30, 90] as const;

export type Tick = { id: string; x: number; windowFrom: number | null; tone: Tone; label: string };

/** Places one tick per certificate with a current version, at its expiry, on
 * a 0..W axis spanning `HORIZON_DAYS` from `now`. Certificates that expire
 * further out (or never issued) don't get a tick; `beyond` counts the
 * former so the caption can still say "N later" instead of silently
 * dropping them. */
export function horizonTicks(certs: CertBrief[], now: number): { ticks: Tick[]; beyond: number } {
  const span = HORIZON_DAYS * DAY;
  const x = (t: number) => Math.max(0, Math.min(1, (t - now) / span)) * W;
  const ticks: Tick[] = [];
  let beyond = 0;
  for (const c of certs) {
    if (!c.notAfter || c.status === 'revoked') continue;
    const end = Date.parse(c.notAfter);
    if (end - now > span) {
      beyond++;
      continue;
    }
    ticks.push({
      id: c.id,
      x: x(end),
      windowFrom: c.nextRenewAt ? x(Date.parse(c.nextRenewAt)) : null,
      tone: validityTone(c, now),
      label: `${c.name}, expires ${relDays(c.notAfter, now)}`,
    });
  }
  return { ticks, beyond };
}

/** Inverse of the tick's own x mapping: an SVG-space pixel span back to
 * whole days from now, low then high regardless of drag direction. */
export function rangeToDays(x0: number, x1: number): [number, number] {
  const [a, b] = x0 < x1 ? [x0, x1] : [x1, x0];
  return [Math.round((a / W) * HORIZON_DAYS), Math.round((b / W) * HORIZON_DAYS)];
}

/** `beyond` is the server's count of every certificate expiring after the horizon; the briefs only carry the ones that qualified for other reasons. */
type Props = { certs: CertBrief[]; beyond?: number; now: number; range: [number, number] | null; onRange: (r: [number, number] | null) => void };

/** The 90-day expiry horizon: one coloured tick per certificate, the
 * renewal window shaded behind it, and a drag-to-brush range that reports
 * back in whole days. `viewBox` with `preserveAspectRatio="none"` keeps it
 * inside the page width at any viewport (no horizontal scroll). */
export function ExpiryHorizon({ certs, beyond: beyondAll, now, range, onRange }: Props) {
  const ref = useRef<SVGSVGElement>(null);
  const [drag, setDrag] = useState<[number, number] | null>(null);
  const { ticks, beyond: beyondLocal } = horizonTicks(certs, now);
  const beyond = beyondAll ?? beyondLocal;
  const toX = (clientX: number) => {
    const r = ref.current!.getBoundingClientRect();
    return Math.max(0, Math.min(W, ((clientX - r.left) / Math.max(r.width, 1)) * W));
  };
  const sel = drag ?? (range ? ([(range[0] / HORIZON_DAYS) * W, (range[1] / HORIZON_DAYS) * W] as [number, number]) : null);
  return (
    <figure className="grid gap-1">
      <figcaption className="flex items-center gap-1.5 text-base font-semibold">
        Expiry, next 90 days
        <HelpTip id="overview.horizon" />
        {beyond > 0 && <span className="text-xs font-normal text-ink-muted">{beyond} later</span>}
      </figcaption>
      <svg
        ref={ref}
        role="img"
        aria-label={`${ticks.length} certificates expire in the next 90 days`}
        viewBox={`0 0 ${W} 56`}
        preserveAspectRatio="none"
        className="h-14 w-full cursor-crosshair touch-none bg-subtle"
        onPointerDown={(e) => {
          e.currentTarget.setPointerCapture?.(e.pointerId);
          const x = toX(e.clientX);
          setDrag([x, x]);
        }}
        onPointerMove={(e) => drag && setDrag([drag[0], toX(e.clientX)])}
        onPointerUp={() => {
          if (!drag) return;
          const [a, b] = rangeToDays(drag[0], drag[1]);
          setDrag(null);
          onRange(b - a >= 1 ? [a, b] : null);
        }}
        // A pointer that never fires up — captured then interrupted by a
        // browser gesture, a window/tab switch, or (in tests) an unmount —
        // must still end the drag; otherwise `drag` stays set and the next
        // pointerdown's `onPointerMove` jumps from a stale anchor.
        onPointerCancel={() => setDrag(null)}
      >
        {ticks.map((t) =>
          t.windowFrom === null ? null : (
            <rect key={`w-${t.id}`} x={t.windowFrom} y={8} width={Math.max(t.x - t.windowFrom, 0)} height={40} fill="var(--cf-expiring)" opacity={0.12} />
          ),
        )}
        {[30, 60].map((d) => (
          <line key={d} x1={(d / HORIZON_DAYS) * W} x2={(d / HORIZON_DAYS) * W} y1={0} y2={56} stroke="var(--cf-border)" strokeWidth={1} vectorEffect="non-scaling-stroke" />
        ))}
        {ticks.map((t) => (
          <line key={t.id} x1={t.x} x2={t.x} y1={6} y2={50} stroke={`var(${TONE_VAR[t.tone]})`} strokeWidth={2} vectorEffect="non-scaling-stroke">
            <title>{t.label}</title>
          </line>
        ))}
        {sel && <rect x={Math.min(sel[0], sel[1])} y={0} width={Math.abs(sel[1] - sel[0])} height={56} fill="var(--cf-primary)" opacity={0.15} />}
      </svg>
      <div role="group" aria-label="Expiry range presets" className="flex items-center gap-1.5">
        {PRESETS.map((d) => {
          // Derived from `range`, so a brush selection clears or updates it.
          const active = range?.[0] === 0 && range[1] === d;
          return (
            <Tooltip key={d}>
              <TooltipTrigger asChild>
                <Button size="sm" variant={active ? 'secondary' : 'outline'} aria-pressed={active} onClick={() => onRange(active ? null : [0, d])}>
                  {d} d
                </Button>
              </TooltipTrigger>
              <TooltipContent>{active ? 'Clear the range' : `Show certificates expiring within ${d} days`}</TooltipContent>
            </Tooltip>
          );
        })}
      </div>
      <div className="flex justify-between text-xs text-ink-muted" aria-hidden>
        <span>Today</span>
        <span>30 d</span>
        <span>60 d</span>
        <span>90 d</span>
      </div>
    </figure>
  );
}
