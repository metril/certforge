import { CircleAlert, CircleCheck, FlaskConical } from 'lucide-react';
import { useProbeAdcs } from '@/api/queries/cas';
import { errorMessage } from '@/api/errors';
import type { AdcsProbeRequest } from '@/api/types';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { useMe } from '@/lib/org';
import { can } from '@/lib/permissions';
import { ADCS_PROBE_BLOCKED } from './caBody';

/** Opens the AD CS test. Disabled behind PermissionTip without cas:write, or
 * behind a tooltip naming the missing settings (`request` null). */
export function AdcsTestButton({ canWrite, request, onClick }: { canWrite: boolean; request: AdcsProbeRequest | null; onClick: () => void }) {
  const btn = (
    <Button type="button" variant="outline" disabled={!canWrite || !request} onClick={onClick}>
      <FlaskConical className="size-3.5" aria-hidden />
      Test
    </Button>
  );
  if (!canWrite) return <PermissionTip allowed={false} action="cas:write">{btn}</PermissionTip>;
  if (!request) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <span tabIndex={0} className="inline-flex">
            {btn}
          </span>
        </TooltipTrigger>
        <TooltipContent side="top">{ADCS_PROBE_BLOCKED}</TooltipContent>
      </Tooltip>
    );
  }
  return btn;
}

type Props = { orgId: string; name: string; request: AdcsProbeRequest; onOpenChange: (open: boolean) => void };

/** Reads the enrollment policy with `request` and judges its template by the
 * create/update rules (modeled on TestCredentialDialog). */
export function AdcsTestDialog({ orgId, name, request, onOpenChange }: Props) {
  const me = useMe();
  const canWrite = can(me, 'cas:write', orgId);
  const test = useProbeAdcs(orgId);
  const data = test.isSuccess ? test.data : undefined;
  const failure = data && (!data.ok ? data.error || 'Test failed.' : data.selected && !data.selected.usable ? `${data.selected.name}: ${data.selected.reason ?? 'not usable'}` : null);

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Test {name || 'AD CS'}</DialogTitle>
          <DialogDescription className="sr-only">Read the enrollment policy and check the template</DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            // The CA sheet's own <form> is an ancestor in the React tree;
            // a portal still bubbles React events, so stop it here.
            e.preventDefault();
            e.stopPropagation();
            if (canWrite) test.mutate(() => request);
          }}
        >
          <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
            <div className="grid min-w-0 gap-0.5">
              <dt className="text-xs text-ink-muted">Template</dt>
              <dd className="truncate font-mono text-xs">{request.template ?? '–'}</dd>
            </div>
            <div className="grid min-w-0 gap-0.5">
              <dt className="text-xs text-ink-muted">Policy</dt>
              <dd className="truncate font-mono text-xs">{request.cepUrl}</dd>
            </div>
          </dl>
          <div aria-live="polite" className="min-h-5">
            {/* A 200 with ok:false, or an unusable template, is a failure. */}
            {data && !failure && (
              <p className="flex items-center gap-1.5 text-sm">
                <CircleCheck className="size-4 text-valid" aria-hidden />
                {data.selected ? `Works with ${data.selected.name}` : `Policy read: ${data.templates.length} templates`}
              </p>
            )}
            {failure && (
              <p role="alert" className="flex items-center gap-1.5 text-sm">
                <CircleAlert className="size-4 shrink-0 text-failed" aria-hidden />
                {failure}
              </p>
            )}
            {test.isError && (
              // errorMessage appends "Retry in Ns." for a 503 from the probe semaphore.
              <p role="alert" className="flex items-center gap-1.5 text-sm">
                <CircleAlert className="size-4 shrink-0 text-failed" aria-hidden />
                {errorMessage(test.error)}
              </p>
            )}
          </div>
          <DialogFooter>
            <PermissionTip allowed={canWrite} action="cas:write">
              <Button type="submit" disabled={test.isPending || !canWrite}>
                {test.isPending ? 'Testing…' : 'Run test'}
              </Button>
            </PermissionTip>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
