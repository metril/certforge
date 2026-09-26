import { z } from 'zod';

export const clientDetailSearch = z.object({
  /** Expanded grant row (Overview's drift and failed items link here). */
  open: z.string().regex(/^[\w-]{1,64}$/).optional().catch(undefined),
  /** 'new' opens the grant sheet; a grant id opens it on that grant. */
  grant: z.string().regex(/^[\w-]{1,64}$/).optional().catch(undefined),
});
export type ClientDetailSearch = z.infer<typeof clientDetailSearch>;
