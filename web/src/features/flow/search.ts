import { z } from 'zod';

export const FLOW_KINDS = ['ca', 'account', 'dnsCredential', 'certificate', 'layout', 'target', 'hook', 'client', 'channel'] as const;
export const FLOW_STATUSES = ['failed', 'expired', 'drift', 'expiring', 'pending', 'valid', 'idle'] as const;

/**
 * `focus` is the selected node id (kind:uuid); `q` filters nodes by name;
 * `kind`, `status`, `issuer` and `client` narrow by node kind, status and
 * the issuer / client nodes a path must run through. `status=problems` is the
 * legacy alias for the four problem statuses. `edge` (`from>to`) is a selected
 * connection; `more` lists the groups shown past their cap; `collapsed` lists
 * the collapsed group ids (a lane, or a lane.subgroup). Arrays decode from a
 * JSON array or repeated keys, like the events page, and are omitted when empty.
 */
export const flowSearch = z.object({
  focus: z.string().optional().catch(undefined),
  q: z.string().optional().catch(undefined),
  kind: z.array(z.enum(FLOW_KINDS)).optional().catch(undefined),
  status: z.union([z.array(z.enum(FLOW_STATUSES)), z.literal('problems')]).optional().catch(undefined),
  issuer: z.array(z.string()).optional().catch(undefined),
  client: z.array(z.string()).optional().catch(undefined),
  edge: z.string().optional().catch(undefined),
  more: z.array(z.string()).optional().catch(undefined),
  collapsed: z.array(z.string()).optional().catch(undefined),
});
export type FlowSearch = z.infer<typeof flowSearch>;
