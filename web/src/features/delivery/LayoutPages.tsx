import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Navigate } from '@tanstack/react-router';
import { toast } from 'sonner';
import { layoutsQuery } from '@/api/queries/delivery';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { LayoutForm } from './LayoutForm';

export function NewLayoutPage() {
  const org = useOrg();
  const me = useMe();
  if (!can(me, 'delivery:write', org.id)) return <Navigate to="/o/$org/delivery/layouts" params={{ org: org.slug }} replace />;
  return <LayoutForm orgId={org.id} orgSlug={org.slug} />;
}

function Gone({ orgSlug }: { orgSlug: string }) {
  useEffect(() => void toast.error('File layout not found.', { id: 'layout-not-found' }), []);
  return <Navigate to="/o/$org/delivery/layouts" params={{ org: orgSlug }} replace />;
}

export function EditLayoutPage({ id }: { id: string }) {
  const org = useOrg();
  const me = useMe();
  const q = useQuery(layoutsQuery(org.id));
  const layout = q.data?.find((l) => l.id === id);
  if (q.isSuccess && !layout) return <Gone orgSlug={org.slug} />;
  if (!layout) return <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>;
  return <LayoutForm key={layout.id} orgId={org.id} orgSlug={org.slug} layout={layout} readOnly={!can(me, 'delivery:write', org.id)} />;
}
