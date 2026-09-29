import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { TargetsPage } from '@/features/delivery/TargetsPage';

export const Route = createFileRoute('/_app/o/$org/delivery/targets')({
  validateSearch: z.object({
    edit: z.string().regex(/^[\w-]{1,64}$/).optional().catch(undefined),
    // Detail sheet for a server-run target (Task 9); Task 8 only wires the
    // navigation (the "Grants" row action), matching cas.tsx's ?view=.
    view: z.string().regex(/^[\w-]{1,64}$/).optional().catch(undefined),
  }),
  component: TargetsPage,
});
