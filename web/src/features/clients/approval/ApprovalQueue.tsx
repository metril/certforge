import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { useNavigate } from '@tanstack/react-router';
import { CircleX, Clock, X } from 'lucide-react';
import { toast } from 'sonner';
import { pendingEnrollmentsKey, useApproveEnrollment, useRejectEnrollment, usePendingApprovals } from '@/api/queries/enrollments';
import { sitesQuery } from '@/api/queries/sites';
import type { EnrollmentRequest } from '@/api/types';
import { Card, CardHeader } from '@/components/Card';
import { IconButton } from '@/components/IconButton';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { useMe, useOrg } from '@/lib/org';
import { can } from '@/lib/permissions';
import { HOUR, relTime } from '@/lib/time';
import { cn } from '@/lib/utils';
import { ApproveDialog } from './ApproveDialog';
import { RejectDialog } from './RejectDialog';

export function isExpired(r: EnrollmentRequest, now = Date.now()): boolean {
  return Date.parse(r.expiresAt) <= now;
}

/** Requests still approvable: the nav badge and the Overview count these. */
export const live = (rs: EnrollmentRequest[]) => rs.filter((r) => !isExpired(r));

/** Dialogs plus the approve/reject mutations, shared by the queue and the Enrol page. */
export function useApprovalFlow(orgId: string) {
  const org = useOrg();
  const navigate = useNavigate();
  const qc = useQueryClient();
  const approve = useApproveEnrollment(orgId);
  const reject = useRejectEnrollment(orgId);
  const { data: sites = [] } = useQuery(sitesQuery(orgId));
  const [reviewId, setReviewId] = useState<string | null>(null);
  const [rejecting, setRejecting] = useState<EnrollmentRequest | null>(null);
  const doReject = async (r: EnrollmentRequest) => {
    await reject.mutateAsync(r.id);
    qc.setQueryData<EnrollmentRequest[]>(pendingEnrollmentsKey(orgId), (old) => old?.filter((x) => x.id !== r.id));
    toast(`Rejected ${r.clientName}`, {
      action: { label: 'New token', onClick: () => void navigate({ to: '/o/$org/clients/$id', params: { org: org.slug, id: r.clientId } }) },
    });
  };
  return {
    review: setReviewId,
    reject: setRejecting,
    /** Expired rows: nothing left to decide, so no confirmation. */
    dismiss: (r: EnrollmentRequest) => void doReject(r).catch(() => undefined),
    dialogs: (requests: EnrollmentRequest[]) => {
      const reviewing = requests.find((r) => r.id === reviewId) ?? null;
      return (
        <>
          <ApproveDialog
            request={reviewing}
            siteName={sites.find((s) => s.id === reviewing?.siteId)?.name}
            onOpenChange={(o) => !o && setReviewId(null)}
            onApprove={async (r) => {
              await approve.mutateAsync(r.id);
              // Gone from the queue at once, without waiting for the refetch.
              qc.setQueryData<EnrollmentRequest[]>(pendingEnrollmentsKey(orgId), (old) => old?.filter((x) => x.id !== r.id));
              toast.success(`Approved ${r.clientName}. It connects within a few seconds.`);
            }}
            onReject={(r) => {
              setReviewId(null);
              setRejecting(r);
            }}
            onHandled={() => void qc.invalidateQueries({ queryKey: pendingEnrollmentsKey(orgId) })}
          />
          <RejectDialog
            request={rejecting}
            onOpenChange={(o) => !o && setRejecting(null)}
            onConfirm={doReject}
          />
        </>
      );
    },
  };
}

/** "Awaiting approval": agents that proved the token and wait for an admin.
 * Rendered only in a single org, with clients:write, while the count is above
 * zero. Not affected by the list filters. */
export function ApprovalQueue() {
  const org = useOrg();
  const me = useMe();
  const canWrite = can(me, 'clients:write', org.id);
  const requests = usePendingApprovals(org.id, canWrite);
  const flow = useApprovalFlow(org.id);
  if (!canWrite || requests.length === 0) return null;
  const waiting = live(requests).length;
  return (
    <Card id="approvals" role="region" aria-label="Awaiting approval" className="mb-4">
      <CardHeader title="Awaiting approval">
        <span aria-live="polite">
          <ToneChip tone="pending" icon={Clock} label={String(waiting)} />
        </span>
      </CardHeader>
      <ul className="grid divide-y divide-border">
        {requests.map((r) => {
          const expired = isExpired(r);
          const soon = !expired && Date.parse(r.expiresAt) - Date.now() < HOUR;
          return (
            <li key={r.id} aria-label={r.hostname} className={cn('flex flex-wrap items-center gap-x-4 gap-y-2 px-4 py-3 text-sm', expired && 'opacity-70')}>
              <div className="grid min-w-0 flex-1 basis-56 gap-0.5">
                <span className="truncate font-mono font-semibold">{r.hostname}</span>
                <span className="truncate text-xs text-ink-muted">
                  {r.os}/{r.arch} · {r.agentVersion} · <span className="font-mono">{r.sourceIp}</span>
                </span>
                <span className="truncate text-xs text-ink-muted">
                  Token for {r.clientName} · requested {relTime(r.createdAt)}
                </span>
              </div>
              {expired ? (
                <ToneChip tone="failed" icon={CircleX} label="Expired" />
              ) : (
                <ToneChip tone={soon ? 'expiring' : 'neutral'} icon={Clock} label={`Expires ${relTime(r.expiresAt)}`} />
              )}
              <div className="flex items-center gap-2">
                {expired ? (
                  <IconButton label="Dismiss" variant="ghost" size="icon" onClick={() => flow.dismiss(r)}>
                    <X className="size-4" aria-hidden />
                  </IconButton>
                ) : (
                  <>
                    <Button onClick={() => flow.review(r.id)}>Review</Button>
                    <IconButton label="Reject" tip="Refuses the agent and spends its token." variant="ghost" size="icon" onClick={() => flow.reject(r)}>
                      <X className="size-4" aria-hidden />
                    </IconButton>
                  </>
                )}
              </div>
            </li>
          );
        })}
      </ul>
      {flow.dialogs(requests)}
    </Card>
  );
}
