import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { TargetsPage } from '@/features/delivery/TargetsPage';

export const Route = createFileRoute('/_app/o/$org/delivery/targets')({
  validateSearch: z.object({ edit: z.string().regex(/^[\w-]{1,64}$/).optional().catch(undefined) }),
  component: TargetsPage,
});
