import { z } from 'zod';

/** `focus` is the selected node id (kind:uuid). */
export const flowSearch = z.object({ focus: z.string().optional().catch(undefined) });
export type FlowSearch = z.infer<typeof flowSearch>;
