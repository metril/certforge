import { useState } from 'react';
import { CircleAlert, CircleCheck } from 'lucide-react';
import { useTestCredential } from '@/api/queries/dns';
import { errorMessage } from '@/api/errors';
import type { DnsCredential } from '@/api/types';
import { Field } from '@/components/Field';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { normalizeZone } from '@/lib/zone';

type Props = { orgId: string; credential: DnsCredential; onOpenChange: (open: boolean) => void };

export function TestCredentialDialog({ orgId, credential, onOpenChange }: Props) {
  const test = useTestCredential(orgId);
  const [zone, setZone] = useState('');
  // Fix round 1: accept a pasted URL, but reject spaces/empty labels rather
  // than sending them to the API as-is.
  const normalized = normalizeZone(zone);
  const zoneError = zone.trim() && !normalized ? 'Enter a valid hostname' : null;

  return (
    <Dialog open onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Test {credential.name}</DialogTitle>
          <DialogDescription className="sr-only">Write and remove a TXT record in a zone</DialogDescription>
        </DialogHeader>
        <form
          className="grid gap-4"
          onSubmit={(e) => {
            e.preventDefault();
            if (normalized) test.mutate({ id: credential.id, zone: normalized });
          }}
        >
          <Field id="test-zone" label="Zone" help="dns.test" error={zoneError}>
            <Input id="test-zone" className="font-mono text-xs" value={zone} onChange={(e) => setZone(e.target.value)} placeholder="example.com" disabled={test.isPending} />
          </Field>
          <div aria-live="polite" className="min-h-5">
            {/* preflight A15 (Critical): a 200 with ok:false is still a
                failure — branch on data.ok, don't render success for every 200. */}
            {test.isSuccess && test.data.ok && (
              <p className="flex items-center gap-1.5 text-sm">
                <CircleCheck className="size-4 text-valid" aria-hidden />
                Works for {test.variables?.zone ?? normalized ?? zone}
              </p>
            )}
            {test.isSuccess && !test.data.ok && (
              <p role="alert" className="flex items-center gap-1.5 text-sm">
                <CircleAlert className="size-4 text-failed" aria-hidden />
                {test.data.error || 'Test failed.'}
              </p>
            )}
            {test.isError && (
              // errorMessage appends "Retry in Ns." for a 503 from the test
              // semaphore (ApiError.retryAfter, parsed from Retry-After).
              <p role="alert" className="flex items-center gap-1.5 text-sm">
                <CircleAlert className="size-4 text-failed" aria-hidden />
                {errorMessage(test.error)}
              </p>
            )}
          </div>
          <DialogFooter>
            <Button type="submit" disabled={!normalized || test.isPending}>
              {test.isPending ? 'Testing…' : 'Run test'}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}
