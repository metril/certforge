import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { MonitorsPage } from '@/features/alerts/MonitorsPage';

export const Route = createFileRoute('/_app/o/$org/alerts/monitors/')({
  validateSearch: z.object({
    // A grant-owned monitor's read-only "managed by a grant" sheet.
    managed: z.string().optional().catch(undefined),
  }),
  component: MonitorsPage,
});
