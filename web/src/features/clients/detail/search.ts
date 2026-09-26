import { z } from 'zod';

// Task 5 adds `grant` (open the grant sheet).
export const clientDetailSearch = z.object({
  /** Expanded grant row (Overview's drift and failed items link here). */
  open: z.string().regex(/^[\w-]{1,64}$/).optional().catch(undefined),
});
export type ClientDetailSearch = z.infer<typeof clientDetailSearch>;
