import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { ActionsPage } from '@/features/delivery/ActionsPage';

export const Route = createFileRoute('/_app/o/$org/delivery/actions')({
  validateSearch: z.object({ tab: z.enum(['actions', 'groups']).optional().catch(undefined), edit: z.string().regex(/^[\w-]{1,64}$/).optional().catch(undefined) }),
  component: ActionsPage,
});
