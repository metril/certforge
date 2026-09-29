import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { MonitorsPage } from '@/features/alerts/MonitorsPage';

export const Route = createFileRoute('/_app/o/$org/alerts/monitors')({
  validateSearch: z.object({
    // Detail/create sheet (task 4): `edit=new` or an existing monitor id.
    edit: z.string().optional().catch(undefined),
  }),
  component: MonitorsPage,
});
