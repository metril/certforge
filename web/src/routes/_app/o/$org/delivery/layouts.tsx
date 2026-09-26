import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { LayoutsPage } from '@/features/delivery/LayoutsPage';

export const Route = createFileRoute('/_app/o/$org/delivery/layouts')({
  validateSearch: z.object({ edit: z.string().regex(/^[\w-]{1,64}$/).optional().catch(undefined) }),
  component: LayoutsPage,
});
