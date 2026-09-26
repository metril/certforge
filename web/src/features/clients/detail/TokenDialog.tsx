import type { ClientCreated } from '@/api/types';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { TokenPanel } from '../enrol/TokenPanel';

/** A re-issued enrolment token. Unlike an API key, a lost token is cheap to
 * re-issue, so there is no "stored safely" gate; closing forgets it. */
export function TokenDialog({ created, onDone }: { created: ClientCreated | null; onDone: () => void }) {
  return (
    <Dialog open={created !== null} onOpenChange={(open) => !open && onDone()}>
      <DialogContent className="max-h-[90dvh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>New token for {created?.client.name}</DialogTitle>
          <DialogDescription className="sr-only">One-time enrolment token and run snippets.</DialogDescription>
        </DialogHeader>
        {created && <TokenPanel created={created} />}
        <DialogFooter>
          <Button onClick={onDone}>Done</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
