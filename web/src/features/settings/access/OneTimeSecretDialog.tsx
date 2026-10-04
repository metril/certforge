import { useEffect, useState } from 'react';
import { useBlocker } from '@tanstack/react-router';
import { toast } from 'sonner';
import { CopyField } from '@/components/CopyField';
import { SwitchField } from '@/components/SwitchField';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';

/** Shows a new secret once. It cannot be dismissed until "Stored safely" is
 * on (D4 ruling: no explanatory paragraph — the copy lives in the
 * `apikey.secretOnce` tooltip on the switch instead). */
export function OneTimeSecretDialog({ token, name, onDone }: { token: string | null; name: string; onDone: () => void }) {
  const [stored, setStored] = useState(false);
  useEffect(() => {
    if (!token) setStored(false);
  }, [token]);
  // The key is shown once and lives only in this component's parent: a route
  // change or a tab close before it is acknowledged would lose it.
  const guarding = token !== null && !stored;
  useBlocker({
    shouldBlockFn: () => {
      if (guarding) toast.error('Mark the API key as stored before leaving; it is shown only once.');
      return guarding;
    },
    disabled: !guarding,
    enableBeforeUnload: guarding,
  });
  const block = (e: Event) => {
    if (!stored) e.preventDefault();
  };
  return (
    <Dialog open={token !== null} onOpenChange={(open) => !open && stored && onDone()}>
      <DialogContent onEscapeKeyDown={block} onInteractOutside={block}>
        <DialogHeader>
          <DialogTitle>API key {name}</DialogTitle>
        </DialogHeader>
        <CopyField value={token ?? ''} label="API key" className="w-full" />
        <SwitchField id="key-stored" label="Stored safely" help="apikey.secretOnce" checked={stored} onCheckedChange={setStored} onText="Yes" offText="No" />
        <DialogFooter>
          <Button disabled={!stored} onClick={onDone}>
            Done
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
