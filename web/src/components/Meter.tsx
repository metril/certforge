import { cn } from '@/lib/utils';

export type MeterTone = 'valid' | 'expiring' | 'failed';

const FILL: Record<MeterTone, string> = {
  valid: 'bg-valid',
  expiring: 'bg-expiring',
  failed: 'bg-failed',
};

/** A thin usage/progress bar (`h-1.5`), extracted from `RateLedgerPanel`'s
 * own meter (Task 7) so the Encryption key card's per-table rewrap bars
 * share one element instead of a second copy. Exposed as a `progressbar`
 * (`aria-valuenow`/min/max) for assistive tech and for tests. */
export function Meter({ value, max, tone = 'valid', label, className }: { value: number; max: number; tone?: MeterTone; label?: string; className?: string }) {
  const pct = max > 0 ? Math.min(100, (value / max) * 100) : 0;
  return (
    <div
      role="progressbar"
      aria-valuenow={value}
      aria-valuemin={0}
      aria-valuemax={max}
      aria-label={label}
      className={cn('h-1.5 min-w-16 flex-1 bg-subtle', className)}
    >
      <div className={cn('h-full', FILL[tone])} style={{ width: `${pct}%` }} />
    </div>
  );
}
