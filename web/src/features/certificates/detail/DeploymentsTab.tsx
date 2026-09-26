import { useQuery } from '@tanstack/react-query';
import { Link } from '@tanstack/react-router';
import { RotateCw } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { certificateDeploymentsQuery, useRedeployGrant } from '@/api/queries/grants';
import { sitesQuery } from '@/api/queries/sites';
import type { Certificate, CertificateDeployment } from '@/api/types';
import { ConnectionDot } from '@/components/ConnectionDot';
import { DeploymentChip } from '@/components/DeploymentChip';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { DELIVERY_LABEL, fileRows } from '@/lib/clientStatus';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { cn } from '@/lib/utils';

const COLS = 'md:grid-cols-[minmax(0,1fr)_minmax(0,112px)_56px_minmax(0,120px)_minmax(0,120px)_104px_minmax(0,180px)_112px]';

function installedNote(d: CertificateDeployment, cert: Certificate): string {
  if (!d.deployment.versionId) return 'No version yet';
  const version = d.deployment.versionId === cert.currentVersion?.id ? 'Current version' : 'Older version';
  if (!d.deployment.reportedAt) return version;
  const ok = fileRows(d.deployment).filter((r) => r.match === 'ok').length;
  return `${version} · ${ok}/${d.deployment.expected.length} files match`;
}

// The row carries no real lastSeen (the deployment's updatedAt is not the
// client's last-seen time): pass null and let an explicit label carry the
// Offline/Online word for an active client, falling back to
// ConnectionDot's own Never connected/Revoked reading otherwise.
const connectionOf = (d: CertificateDeployment) => ({ status: d.clientStatus, online: d.clientOnline, lastSeen: null });
const connectionLabel = (d: CertificateDeployment) => (d.clientStatus === 'active' && !d.clientOnline ? 'Offline' : undefined);

/** A layout or target name linking to its Delivery sheet; "–" when the grant has none. */
function DeliveryRef({ orgSlug, kind, id, name }: { orgSlug: string; kind: 'layouts' | 'targets'; id: string | null; name: string | null }) {
  if (!id) return <span className="text-ink-muted">–</span>;
  return (
    <Link
      to={kind === 'layouts' ? '/o/$org/delivery/layouts' : '/o/$org/delivery/targets'}
      params={{ org: orgSlug }}
      search={{ edit: id }}
      className="truncate hover:underline"
    >
      {name ?? id}
    </Link>
  );
}

export function DeploymentsTab({ cert, orgId, orgSlug }: { cert: Certificate; orgId: string; orgSlug: string }) {
  const me = useMe();
  const allowed = can(me, 'clients:read', orgId);
  const canWrite = can(me, 'clients:write', orgId);
  const q = useQuery({ ...certificateDeploymentsQuery(orgId, cert.id), enabled: allowed });
  const { data: sites = [] } = useQuery({ ...sitesQuery(orgId), enabled: allowed });
  const redeploy = useRedeployGrant(orgId);
  if (!allowed) return <EmptyState message="Needs the clients:read permission." />;
  if (q.isError) return <ErrorState message={`Couldn't load deployments. ${errorMessage(q.error)}`} onRetry={() => void q.refetch()} />;
  if (q.isPending) return <p className="text-ink-muted">Loading…</p>;
  if (q.data.length === 0) {
    return (
      <EmptyState message="Not granted to any client yet.">
        <Button asChild variant="outline">
          <Link to="/o/$org/clients" params={{ org: orgSlug }}>
            Open clients
          </Link>
        </Button>
      </EmptyState>
    );
  }
  const siteName = (id: string | null) => (id ? (sites.find((s) => s.id === id)?.name ?? '–') : '–');
  return (
    <div className="grid gap-2">
      <div className={cn('hidden gap-3 border-b border-border pb-1 text-xs text-ink-muted md:grid', COLS)}>
        <span className="inline-flex items-center gap-1">
          Client <HelpTip id="cert.deployments" />
        </span>
        <span>Site</span>
        <span>Delivery</span>
        <span className="inline-flex items-center gap-1">
          Layout <HelpTip id="grant.layout" />
        </span>
        <span className="inline-flex items-center gap-1">
          Target <HelpTip id="grant.target" />
        </span>
        <span>State</span>
        <span>Installed</span>
        <span />
      </div>
      <ul aria-label="Deployments" className="grid">
        {q.data.map((d) => (
          <li key={d.grantId} className={cn('grid grid-cols-[minmax(0,1fr)_auto] items-center gap-x-3 gap-y-1 border-b border-border py-2 text-sm last:border-0 md:min-h-9 md:py-1', COLS)}>
            <span className="flex min-w-0 items-center gap-2">
              <Link
                to="/o/$org/clients/$id/$tab"
                params={{ org: orgSlug, id: d.clientId, tab: 'certificates' }}
                search={{ open: d.grantId }}
                className="truncate font-semibold hover:underline"
              >
                {d.clientName}
              </Link>
              <ConnectionDot client={connectionOf(d)} label={connectionLabel(d)} />
            </span>
            <span className="truncate">{siteName(d.siteId)}</span>
            <span>{DELIVERY_LABEL[d.delivery]}</span>
            <DeliveryRef orgSlug={orgSlug} kind="layouts" id={d.layoutId} name={d.layoutName} />
            <DeliveryRef orgSlug={orgSlug} kind="targets" id={d.deployTargetId} name={d.deployTargetName} />
            <DeploymentChip state={d.deployment.state} withHelp />
            <span className="truncate text-xs text-ink-muted">{installedNote(d, cert)}</span>
            <PermissionTip allowed={canWrite} action="clients:write" side="left">
              <Button
                size="sm"
                variant="outline"
                disabled={!canWrite || d.clientStatus === 'revoked' || (redeploy.isPending && redeploy.variables === d.grantId)}
                onClick={() => redeploy.mutate(d.grantId)}
              >
                <RotateCw className="size-3.5" aria-hidden />
                Redeploy
              </Button>
            </PermissionTip>
          </li>
        ))}
      </ul>
    </div>
  );
}
