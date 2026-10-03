import { Link } from '@tanstack/react-router';
import { useQuery } from '@tanstack/react-query';
import { allCertificatesQuery, allOrgsCertificatesQuery } from '@/api/queries/certificates';
import { agentCAsQuery } from '@/api/queries/agents';
import { errorMessage } from '@/api/errors';
import { readinessQuery } from '@/api/queries/health';
import { EmptyState } from '@/components/EmptyState';
import { ErrorState } from '@/components/ErrorState';
import { PageHeader } from '@/components/PageHeader';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { can } from '@/lib/permissions';
import { useAllOrgs, useMe, useOrg } from '@/lib/org';
import { statusCounts } from './attention';
import { AttentionBlock } from './blocks/AttentionBlock';
import { InsightsCard } from './blocks/InsightsCard';
import { StatusRow } from './blocks/StatusRow';
import { HealthStrip } from './HealthStrip';

export function OverviewPage() {
  const org = useOrg();
  const allOrgs = useAllOrgs();
  const me = useMe();
  const { data, isPending, isError, error, refetch } = useQuery(allOrgs ? allOrgsCertificatesQuery : allCertificatesQuery(org.id));
  const certs = data ?? [];
  const readiness = useQuery(readinessQuery);
  const agentCAs = useQuery({ ...agentCAsQuery, enabled: can(me, 'settings:read') });
  const now = Date.now();

  if (isError && !data) {
    return (
      <>
        <PageHeader title="Overview" help="overview.page" />
        <ErrorState message={`Couldn't load certificates. ${errorMessage(error)}`} onRetry={() => void refetch()} />
      </>
    );
  }

  if (!isPending && certs.length === 0) {
    return (
      <>
        <PageHeader title="Overview" help="overview.page" />
        <div className="grid gap-6">
          <HealthStrip readiness={readiness.data} listener={agentCAs.data?.listener} />
          <EmptyState message="No certificates yet.">
            {!allOrgs &&
              (can(me, 'certs:write', org.id) ? (
                <Button asChild>
                  <Link to="/o/$org/certificates/new" params={{ org: org.slug }}>
                    New certificate
                  </Link>
                </Button>
              ) : (
                <PermissionTip allowed={false} action="certs:write">
                  <Button disabled>New certificate</Button>
                </PermissionTip>
              ))}
          </EmptyState>
        </div>
      </>
    );
  }

  const counts = statusCounts(certs);

  return (
    <>
      <PageHeader title="Overview" help="overview.page" />
      <div className="grid gap-6">
        {isError && (
          <p role="status" className="text-sm text-expiring">
            Couldn't refresh certificates, showing the last loaded data. {errorMessage(error)}
          </p>
        )}
        <StatusRow counts={counts} orgSlug={org.slug} readiness={readiness.data} listener={agentCAs.data?.listener} />
        <AttentionBlock certs={certs} now={now} />
        <InsightsCard certs={certs} now={now} />
      </div>
    </>
  );
}
