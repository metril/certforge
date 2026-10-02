import { z } from 'zod';

/**
 * `focus` is the selected node id (kind:uuid); `q` filters nodes by name;
 * `status=problems` keeps only nodes (and edges) that need attention;
 * `collapsed` lists the collapsed group ids (a lane, or a lane.subgroup).
 * Arrays decode from a JSON array or repeated keys, like the events page.
 */
export const flowSearch = z.object({
  focus: z.string().optional().catch(undefined),
  q: z.string().optional().catch(undefined),
  status: z.literal('problems').optional().catch(undefined),
  collapsed: z.array(z.string()).optional().catch(undefined),
});
export type FlowSearch = z.infer<typeof flowSearch>;
