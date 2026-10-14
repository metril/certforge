import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Navigate } from '@tanstack/react-router';
import { toast } from 'sonner';
import { casQuery } from '@/api/queries/cas';
import { isPrivate, kindOf } from '@/lib/caKinds';
import { useOrg } from '@/lib/org';
import { CaDetail, type CaTab } from './CaDetail';

function Gone({ orgSlug }: { orgSlug: string }) {
  useEffect(() => void toast.error('CA not found.', { id: 'ca-not-found' }), []);
  return <Navigate to="/o/$org/issuers/cas" params={{ org: orgSlug }} replace />;
}

export function CaDetailPage({ id, tab }: { id: string; tab: CaTab }) {
  const org = useOrg();
  const q = useQuery(casQuery(org.id));
  const ca = q.data?.find((c) => c.id === id);
  if (q.isSuccess && !ca) return <Gone orgSlug={org.slug} />;
  // Only private CAs have a detail page; any other kind opens its sheet on the list.
  if (ca && !isPrivate(ca)) return <Navigate to="/o/$org/issuers/cas" params={{ org: org.slug }} search={{ edit: ca.id, kind: kindOf(ca) }} replace />;
  if (!ca) return <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>;
  return <CaDetail orgId={org.id} orgSlug={org.slug} ca={ca} tab={tab} />;
}
