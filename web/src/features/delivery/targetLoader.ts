import { redirect } from '@tanstack/react-router';
import { toast } from 'sonner';
import { deployTargetsQuery } from '@/api/queries/delivery';
import type { QueryClient } from '@tanstack/react-query';

/** Route loader for a target page: an unknown id goes back to the list with a toast. */
export async function targetLoader({ context: { queryClient, org }, params }: { context: { queryClient: QueryClient; org: { id: string; slug: string } }; params: { id: string } }) {
  const targets = await queryClient.ensureQueryData(deployTargetsQuery(org.id));
  const target = targets.find((t) => t.id === params.id);
  if (!target) {
    toast.error('Deploy target not found.', { id: 'target-not-found' });
    throw redirect({ to: '/o/$org/delivery/targets', params: { org: org.slug } });
  }
  return target;
}
