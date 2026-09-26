import { useEffect, useState, type ReactNode } from 'react';
import { CircleAlert } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import type { HelpKey } from '@/lib/help';
import { HelpTip } from './HelpTip';

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  title: string;
  consequence: string;
  help?: HelpKey;
  confirmText: string;
  actionLabel: string;
  onConfirm: () => Promise<unknown>;
  /** Extra controls (e.g. a force-delete switch) rendered above the confirm
   * input; existing callers are unaffected. */
  children?: ReactNode;
};

export function ConfirmDestructive({ open, onOpenChange, title, consequence, help, confirmText, actionLabel, onConfirm, children }: Props) {
  const [typed, setTyped] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (!open) {
      setTyped('');
      setError(null);
    }
  }, [open]);

  async function run() {
    setBusy(true);
    setError(null);
    try {
      await onConfirm();
      onOpenChange(false);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>{title}</DialogTitle>
          <DialogDescription className="flex items-start gap-1.5">
            <span>{consequence}</span>
            {help && <HelpTip id={help} />}
          </DialogDescription>
        </DialogHeader>
        {children}
        <div className="grid gap-1.5">
          <Label htmlFor="confirm-destructive">
            Type <span className="font-mono">{confirmText}</span> to confirm
          </Label>
          <Input id="confirm-destructive" autoComplete="off" value={typed} onChange={(e) => setTyped(e.target.value)} />
        </div>
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
          <Button variant="destructive" disabled={typed !== confirmText || busy} onClick={() => void run()}>
            {actionLabel}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
