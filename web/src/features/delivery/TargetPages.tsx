import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Navigate } from '@tanstack/react-router';
import { toast } from 'sonner';
import { deployTargetsQuery } from '@/api/queries/delivery';
import { metaSchemasQuery } from '@/api/queries/dns';
import { ErrorState } from '@/components/ErrorState';
import { errorMessage } from '@/api/errors';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { TargetDetail } from './TargetDetail';
import { TargetForm } from './TargetForm';
import type { TargetTab } from './tabs';

function useTypes() {
  const q = useQuery(metaSchemasQuery);
  return { q, types: q.data?.deployTargets ?? [] };
}

/** The target left the cached list after the route loaded (deleted elsewhere): back to the list. */
function Gone({ orgSlug }: { orgSlug: string }) {
  useEffect(() => void toast.error('Deploy target not found.', { id: 'target-not-found' }), []);
  return <Navigate to="/o/$org/delivery/targets" params={{ org: orgSlug }} replace />;
}

function Pending({ error, retry }: { error?: unknown; retry: () => void }) {
  return error ? <ErrorState message={`Couldn't load target types. ${errorMessage(error)}`} onRetry={retry} /> : <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>;
}

export function NewTargetPage() {
  const org = useOrg();
  const me = useMe();
  const { q, types } = useTypes();
  if (!can(me, 'delivery:write', org.id)) return <Navigate to="/o/$org/delivery/targets" params={{ org: org.slug }} replace />;
  if (types.length === 0) return <Pending error={q.error} retry={() => void q.refetch()} />;
  return <TargetForm orgId={org.id} orgSlug={org.slug} types={types} />;
}

export function EditTargetPage({ id }: { id: string }) {
  const org = useOrg();
  const me = useMe();
  const { q, types } = useTypes();
  const tq = useQuery(deployTargetsQuery(org.id));
  const target = tq.data?.find((t) => t.id === id);
  if (tq.isSuccess && !target) return <Gone orgSlug={org.slug} />;
  if (!can(me, 'delivery:write', org.id)) return <Navigate to="/o/$org/delivery/targets/$id/$tab" params={{ org: org.slug, id, tab: 'overview' }} replace />;
  if (!target || types.length === 0) return <Pending error={q.error} retry={() => void q.refetch()} />;
  return <TargetForm key={target.id} orgId={org.id} orgSlug={org.slug} target={target} types={types} />;
}

export function TargetDetailPage({ id, tab }: { id: string; tab: TargetTab }) {
  const org = useOrg();
  const { q, types } = useTypes();
  const tq = useQuery(deployTargetsQuery(org.id));
  const target = tq.data?.find((t) => t.id === id);
  if (tq.isSuccess && !target) return <Gone orgSlug={org.slug} />;
  if (!target || types.length === 0) return <Pending error={q.error} retry={() => void q.refetch()} />;
  return <TargetDetail orgId={org.id} orgSlug={org.slug} target={target} types={types} tab={tab} />;
}
