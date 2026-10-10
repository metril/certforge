import { useEffect, useId, useReducer, useState } from 'react';
import { CircleAlert, CircleX, LoaderCircle } from 'lucide-react';
import { ApiError, errorMessage } from '@/api/errors';
import type { EnrollmentRequest } from '@/api/types';
import { HelpTip } from '@/components/HelpTip';
import { SwitchField } from '@/components/SwitchField';
import { ToneChip } from '@/components/StatusChip';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { relTime } from '@/lib/time';
import { cn } from '@/lib/utils';
import { VerifyCode } from './VerifyCode';

const HANDLED = 'Someone else already handled this request.';

function Fact({ label, children, mono }: { label: string; children: React.ReactNode; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-ink-muted">{label}</dt>
      <dd className={cn('truncate', mono && 'font-mono')}>{children}</dd>
    </div>
  );
}

/** Compare the code with the agent log, confirm, approve. Name and site come
 * from the token's client and are read-only: approving takes no body. */
export function ApproveDialog({
  request,
  siteName,
  onOpenChange,
  onApprove,
  onReject,
  onHandled,
}: {
  request: EnrollmentRequest | null;
  siteName?: string;
  onOpenChange: (open: boolean) => void;
  onApprove: (r: EnrollmentRequest) => Promise<unknown>;
  onReject: (r: EnrollmentRequest) => void;
  /** The request was approved or rejected elsewhere (404/409): refetch. */
  onHandled: () => void;
}) {
  const [matches, setMatches] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const reasonId = useId();
  // One timeout to the expiry flips the dialog without a repeating ticker.
  const [, tick] = useReducer((n: number) => n + 1, 0);
  const expiresAt = request?.expiresAt;
  useEffect(() => {
    setMatches(false);
    setError(null);
  }, [request?.id]);
  useEffect(() => {
    if (!expiresAt) return;
    const ms = Date.parse(expiresAt) - Date.now();
    if (ms <= 0) return;
    const t = window.setTimeout(tick, ms + 50);
    return () => window.clearTimeout(t);
  }, [expiresAt]);

  const expired = !!expiresAt && Date.parse(expiresAt) <= Date.now();
  const reason = expired ? 'This request expired. Issue a new token.' : !matches ? 'Switch on “Code matches the agent log” first.' : null;
  const blocked = reason !== null || busy;

  const approve = async () => {
    if (!request || blocked) return;
    setBusy(true);
    setError(null);
    try {
      await onApprove(request);
      onOpenChange(false);
    } catch (e) {
      if (e instanceof ApiError && (e.status === 404 || e.status === 409)) {
        setError(HANDLED);
        onHandled();
        window.setTimeout(() => onOpenChange(false), 1500);
      } else setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const approveBtn = (
    <Button
      aria-disabled={blocked || undefined}
      aria-describedby={reason ? reasonId : undefined}
      className={cn(blocked && 'cursor-not-allowed opacity-50 hover:bg-primary')}
      onClick={() => void approve()}
    >
      {busy && <LoaderCircle className="size-4 animate-spin motion-reduce:animate-none" aria-hidden />}
      Approve
    </Button>
  );

  return (
    <Dialog open={request !== null} onOpenChange={onOpenChange}>
      <DialogContent
        className="max-h-[90dvh] overflow-y-auto sm:max-w-lg"
        // Focus the switch, not the first HelpTip: one Escape closes the dialog.
        onOpenAutoFocus={(e) => {
          e.preventDefault();
          document.getElementById('approve-matches')?.focus();
        }}
      >
        <DialogHeader>
          <DialogTitle className="flex items-center gap-1.5">
            Approve agent <HelpTip id="enrol.approve" />
          </DialogTitle>
          <DialogDescription className="sr-only">Compare the verification code with the agent log, then approve or reject.</DialogDescription>
        </DialogHeader>
        {request && (
          <>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-xs">
              <Fact label="Client">{request.clientName}</Fact>
              <Fact label="Site">{siteName ?? '–'}</Fact>
              <Fact label="Hostname" mono>
                {request.hostname}
              </Fact>
              <Fact label="OS / arch">
                {request.os}/{request.arch}
              </Fact>
              <Fact label="Agent version">{request.agentVersion}</Fact>
              <Fact label="Source IP" mono>
                {request.sourceIp}
              </Fact>
              <Fact label="Requested">{relTime(request.createdAt)}</Fact>
              <Fact label="Expires">{expired ? 'Expired' : relTime(request.expiresAt)}</Fact>
            </dl>
            <div className={cn('grid justify-items-center gap-2 rounded-md border bg-subtle p-4', expired ? 'border-failed' : 'border-border')}>
              <span className="flex items-center gap-1.5 text-xs text-ink-muted">
                Verification code <HelpTip id="enrol.code" />
              </span>
              <VerifyCode code={request.verifyCode} />
              {expired && <ToneChip tone="failed" icon={CircleX} label="Expired" />}
            </div>
            <SwitchField
              id="approve-matches"
              label="Code matches the agent log"
              help="enrol.codeMatches"
              checked={matches}
              onCheckedChange={setMatches}
              onText="Matches"
              offText="Not checked"
              disabled={busy || expired}
            />
          </>
        )}
        {error && (
          <p role="alert" className="flex items-center gap-1 text-sm">
            <CircleAlert className="size-4 text-failed" aria-hidden />
            {error}
          </p>
        )}
        <DialogFooter className="sm:justify-between">
          <Button variant="ghost" className="text-failed" disabled={busy || !request} onClick={() => request && onReject(request)}>
            Reject
          </Button>
          <div className="flex flex-col-reverse gap-2 sm:flex-row">
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancel
            </Button>
            {reason ? (
              <Tooltip>
                <TooltipTrigger asChild>{approveBtn}</TooltipTrigger>
                <TooltipContent>{reason}</TooltipContent>
              </Tooltip>
            ) : (
              approveBtn
            )}
          </div>
        </DialogFooter>
        {reason && (
          <span id={reasonId} className="sr-only">
            {reason}
          </span>
        )}
      </DialogContent>
    </Dialog>
  );
}
