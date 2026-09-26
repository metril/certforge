import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { HooksPage } from '@/features/delivery/HooksPage';

export const Route = createFileRoute('/_app/o/$org/delivery/hooks')({
  validateSearch: z.object({ edit: z.string().regex(/^[\w-]{1,64}$/).optional().catch(undefined) }),
  component: HooksPage,
});
