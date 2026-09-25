import { useEffect, useState } from 'react';
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
