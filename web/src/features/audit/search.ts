import { z } from 'zod';
import type { AuditFilter } from '@/api/queries/audit';
import { DAY } from '@/lib/time';

const day = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}$/)
  .refine((s) => !Number.isNaN(Date.parse(`${s}T00:00:00`)));

// Every field falls back to "absent" when a hand-edited URL is invalid.
export const auditSearch = z.object({
  from: day.optional().catch(undefined),
  to: day.optional().catch(undefined),
  actor: z.string().regex(/^[\w-]{1,64}$/).optional().catch(undefined),
  action: z.string().regex(/^[a-z_]+\.([a-z_]+)?$/).max(64).optional().catch(undefined),
  resourceType: z.string().regex(/^[a-z_]{1,64}$/).optional().catch(undefined),
  resourceId: z.string().min(1).max(128).optional().catch(undefined),
  q: z.string().min(1).max(200).optional().catch(undefined),
  event: z.coerce.number().int().positive().optional().catch(undefined),
});
export type AuditSearch = z.infer<typeof auditSearch>;

/** Local calendar days; "to" includes that whole day. */
export function toApiFilter(s: AuditSearch, orgId: string | undefined): AuditFilter {
  const start = (d: string) => new Date(`${d}T00:00:00`);
  return {
    from: s.from ? start(s.from).toISOString() : undefined,
    to: s.to ? new Date(start(s.to).getTime() + DAY).toISOString() : undefined,
    actor: s.actor,
    action: s.action,
    resourceType: s.resourceType,
    resourceId: s.resourceId,
    q: s.q,
    orgId,
  };
}
