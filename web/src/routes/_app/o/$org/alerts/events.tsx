import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import { EmptyState } from '@/components/EmptyState';

const eventKind = z.enum([
  'cert.issued', 'cert.renewal_failed', 'cert.expiring', 'cert.expired',
  'deploy.failed', 'deploy.drift', 'client.offline', 'agent.cert_expiring',
  'monitor.mismatch', 'monitor.unreachable', 'monitor.expiring', 'monitor.recovered',
  'backup.completed', 'backup.failed', 'test',
]);
const severity = z.enum(['info', 'warning', 'critical']);

// Task 5 fills this in with EventsPage; until then the tab renders empty.
export const Route = createFileRoute('/_app/o/$org/alerts/events')({
  validateSearch: z.object({
    // Group/kind filter (repeatable) and the severity floor (task 5).
    kind: z.array(eventKind).optional().catch(undefined),
    severity: severity.optional().catch(undefined),
  }),
  component: () => <EmptyState message="No events yet." />,
});
