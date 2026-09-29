import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { EmptyState } from '@/components/EmptyState';

// Task 4 fills this in with MonitorsPage; until then the tab renders empty.
export const Route = createFileRoute('/_app/o/$org/alerts/monitors')({
  validateSearch: z.object({
    edit: z.string().optional().catch(undefined),
  }),
  component: () => <EmptyState message="No monitors yet." />,
});
