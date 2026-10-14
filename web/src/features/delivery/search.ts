import { z } from 'zod';

export const targetDetailSearch = z.object({
  /** Highlighted grant row on the Grants tab (the grants popover links here). */
  open: z.string().regex(/^[\w-]{1,64}$/).optional().catch(undefined),
});
