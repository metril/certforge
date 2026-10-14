import { useState } from 'react';
import { Webhook } from 'lucide-react';
import { useCreateGrantCheckToken, useDeleteGrantCheckToken } from '@/api/queries/grants';
import { errorMessage } from '@/api/errors';
import type { Grant } from '@/api/types';
import { CopyField } from '@/components/CopyField';
import { HelpTip } from '@/components/HelpTip';
import { IconButton } from '@/components/IconButton';
import { Button } from '@/components/ui/button';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';

/** Check hook: a click popover to generate, rotate or revoke the grant's
 * check-now webhook token. The token is only in hand right after generate or
 * rotate (held in state, dropped when the popover closes). */
export function GrantCheckHook({ orgId, grant, canWrite }: { orgId: string; grant: Grant; canWrite: boolean }) {
  const [open, setOpen] = useState(false);
  const [fresh, setFresh] = useState<{ token: string; url: string } | null>(null);
  const create = useCreateGrantCheckToken(orgId);
  const revoke = useDeleteGrantCheckToken(orgId);
  const hasMonitor = !!grant.monitorId;
  const set = !!grant.checkTokenSet;
  const disabled = !hasMonitor || !canWrite;
  const tip = !canWrite ? 'Needs the clients:write permission' : !hasMonitor ? 'Needs a verify endpoint on the grant' : undefined;
  const err = create.error ?? revoke.error;
  const curl = fresh ? `curl -X POST -H "Authorization: Bearer ${fresh.token}" ${fresh.url}` : '';

  const onOpen = (o: boolean) => {
    setOpen(o);
    if (!o) {
      setFresh(null);
      create.reset();
      revoke.reset();
    }
  };

  const generate = () => create.mutate(grant.id, { onSuccess: (r) => setFresh({ token: r.token, url: r.url }) });

  return (
    <Popover open={open && !disabled} onOpenChange={onOpen}>
      <PopoverTrigger asChild>
        <IconButton variant="ghost" size="icon-sm" className="size-7" disabled={disabled} tip={tip} label={`Check hook for ${grant.certificateName}`}>
          <Webhook className={`size-3.5 ${set ? 'text-valid' : ''}`} aria-hidden />
        </IconButton>
      </PopoverTrigger>
      <PopoverContent align="end" className="w-96 max-w-[calc(100vw-2rem)] p-3">
        <div className="grid gap-2.5 text-xs">
          <div className="flex items-center gap-1.5 text-sm font-medium">
            Check hook
            <HelpTip id="grant.checkHook" />
          </div>
          {fresh ? (
            <>
              <p className="text-ink-muted">Copy the token now; it is not shown again.</p>
              <div className="grid gap-0.5">
                <span className="text-ink-muted">Token</span>
                <CopyField value={fresh.token} label="token" wrap />
              </div>
              <div className="grid gap-0.5">
                <span className="text-ink-muted">URL</span>
                <CopyField value={fresh.url} label="URL" wrap />
              </div>
              <div className="grid gap-0.5">
                <span className="text-ink-muted">Example</span>
                <CopyField value={curl} label="curl command" display={`curl -X POST -H "Authorization: Bearer …" ${fresh.url}`} wrap />
              </div>
            </>
          ) : (
            <p className="text-ink-muted">{set ? 'A token is set. Rotate it to get a new one; the old one stops working.' : 'No token yet. Generate one to let a device request an immediate check.'}</p>
          )}
          {err && (
            <p role="alert" className="text-failed">
              {errorMessage(err)}
            </p>
          )}
          <div className="flex justify-end gap-2">
            {set && (
              <Button type="button" size="sm" variant="outline" disabled={revoke.isPending} onClick={() => revoke.mutate(grant.id, { onSuccess: () => setFresh(null) })}>
                Revoke
              </Button>
            )}
            <Button type="button" size="sm" disabled={create.isPending} onClick={generate}>
              {set ? 'Rotate' : 'Generate'}
            </Button>
          </div>
        </div>
      </PopoverContent>
    </Popover>
  );
}
