import { useEffect } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Navigate } from '@tanstack/react-router';
import { toast } from 'sonner';
import { monitorsQuery } from '@/api/queries/monitors';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { MonitorForm, deletedMonitors } from './MonitorForm';
import { MONITOR_LIMIT } from './MonitorsPage';

export function NewMonitorPage() {
  const org = useOrg();
  const me = useMe();
  const count = useQuery(monitorsQuery(org.id)).data?.length ?? 0;
  if (!can(me, 'alerts:write', org.id) || count >= MONITOR_LIMIT) return <Navigate to="/o/$org/alerts/monitors" params={{ org: org.slug }} replace />;
  return <MonitorForm orgId={org.id} orgSlug={org.slug} />;
}

function Gone({ orgSlug }: { orgSlug: string }) {
  useEffect(() => void toast.error('Monitor not found.', { id: 'monitor-not-found' }), []);
  return <Navigate to="/o/$org/alerts/monitors" params={{ org: orgSlug }} replace />;
}

export function EditMonitorPage({ id }: { id: string }) {
  const org = useOrg();
  const q = useQuery(monitorsQuery(org.id));
  const monitor = q.data?.find((m) => m.id === id);
  if (q.isSuccess && !monitor && deletedMonitors.delete(id)) return <Navigate to="/o/$org/alerts/monitors" params={{ org: org.slug }} replace />;
  if (q.isSuccess && !monitor) return <Gone orgSlug={org.slug} />;
  if (!monitor) return <p className="py-10 text-center text-sm text-ink-muted">Loading…</p>;
  // A grant-owned monitor is edited through its grant; the list explains that.
  if (monitor.grantId) return <Navigate to="/o/$org/alerts/monitors" params={{ org: org.slug }} search={{ managed: monitor.id }} replace />;
  return <MonitorForm key={monitor.id} orgId={org.id} orgSlug={org.slug} monitor={monitor} />;
}
