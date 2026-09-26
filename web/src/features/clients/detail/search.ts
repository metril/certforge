import { z } from 'zod';

// Tasks 4 and 5 add `open` (expanded grant) and `grant` (open the grant sheet).
export const clientDetailSearch = z.object({});
export type ClientDetailSearch = z.infer<typeof clientDetailSearch>;
