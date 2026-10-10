import { useEffect, useState } from 'react';
import { CircleAlert } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import type { EnrollmentRequest } from '@/api/types';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';

/** Rejecting is cheap (issue a new token), so there is no type-to-confirm. */
export function RejectDialog({
  request,
  onOpenChange,
  onConfirm,
}: {
  request: EnrollmentRequest | null;
  onOpenChange: (open: boolean) => void;
  onConfirm: (r: EnrollmentRequest) => Promise<unknown>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => setError(null), [request]);
  const run = async () => {
    if (!request || busy) return;
    setBusy(true);
    setError(null);
    try {
      await onConfirm(request);
      onOpenChange(false);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Dialog open={request !== null} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Reject enrolment from {request?.clientName}?</DialogTitle>
          <DialogDescription>The agent is refused and its token is spent. Issue a new token to try again.</DialogDescription>
        </DialogHeader>
        {error && (
          <p role="alert" className="flex items-center gap-1 text-sm">
            <CircleAlert className="size-4 text-failed" aria-hidden />
            {error}
          </p>
        )}
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button variant="destructive" disabled={busy} onClick={() => void run()}>
            Reject
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
