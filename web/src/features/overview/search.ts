import { z } from 'zod';
import { HORIZON_DAYS } from './ExpiryHorizon';

const clampDay = (n: number) => Math.min(HORIZON_DAYS, Math.max(0, Math.round(n)));

// The expiry horizon's brushed range lives in the URL (controller ruling)
// so it survives a reload and can be shared/bookmarked. A malformed or
// out-of-range value (hand-edited, or from an older/newer HORIZON_DAYS)
// is clamped to 0..HORIZON_DAYS and reordered low-then-high rather than
// rejected outright — `.catch` only covers a value that fails to parse as
// a two-number tuple at all (e.g. a single number, or text).
export const overviewSearch = z.object({
  range: z
    .tuple([z.number().finite(), z.number().finite()])
    .transform(([a, b]): [number, number] => {
      const lo = clampDay(Math.min(a, b));
      const hi = clampDay(Math.max(a, b));
      return [lo, hi];
    })
    .optional()
    .catch(undefined),
});
export type OverviewSearch = z.infer<typeof overviewSearch>;
