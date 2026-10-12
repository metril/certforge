import { useQuery } from '@tanstack/react-query';
import { RefreshCw } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { grantPfSenseUsageQuery } from '@/api/queries/grants';
import { HelpTip } from '@/components/HelpTip';
import { Button } from '@/components/ui/button';

type Props = { orgId: string; grantId: string };

// "Used on pfSense by": asks the firewall on demand which services use a
// server grant's certificate. The target restarts exactly these after each
// deploy when its "Restart services that use it" option is on.
export function PfSenseUsage({ orgId, grantId }: Props) {
  const q = useQuery(grantPfSenseUsageQuery(orgId, grantId));
  const data = q.data;
  return (
    <div className="flex min-w-0 flex-wrap items-center gap-2 text-xs">
      <span className="inline-flex items-center gap-1 text-ink-muted">
        Used on pfSense by <HelpTip id="grant.pfsenseUsage" />
      </span>
      {q.isError ? (
        <span role="alert" className="min-w-0 basis-full break-words text-failed">
          {errorMessage(q.error)}
        </span>
      ) : data ? (
        data.refid === null ? (
          <span className="text-ink-muted">Not on the firewall yet</span>
        ) : data.services.length === 0 ? (
          <span className="text-ink-muted">No services use it</span>
        ) : (
          <ul aria-label="Services" className="flex flex-wrap gap-1">
            {data.services.map((s) => (
              <li key={s} className="rounded-sm border border-border bg-subtle px-2 py-0.5">
                {s}
              </li>
            ))}
          </ul>
        )
      ) : null}
      <Button type="button" variant="ghost" size="sm" className="h-6 px-2 text-xs" disabled={q.isFetching} onClick={() => void q.refetch()}>
        <RefreshCw className="size-3" aria-hidden />
        Check usage
      </Button>
    </div>
  );
}
