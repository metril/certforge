import { useState } from 'react';
import { ToggleGroup } from 'radix-ui';
import { Check, CircleAlert, Globe, LoaderCircle } from 'lucide-react';
import { errorMessage } from '@/api/errors';
import { usePeekSshHostKey } from '@/api/queries/ssh';
import type { SshPeekHostKey } from '@/api/types';
import { HelpTip } from '@/components/HelpTip';
import { PermissionTip } from '@/components/PermissionTip';
import { Button } from '@/components/ui/button';
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Input } from '@/components/ui/input';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { help } from '@/lib/help';
import { cn } from '@/lib/utils';

/** Where Fetch acts: the org, and whether the caller holds delivery:write there (the ssh peek endpoint's gate). */
export type HostKeyScope = { orgId: string; canPeek: boolean };

type Props = {
  id: string;
  value: string;
  onChange: (v: string) => void;
  label?: string;
  disabled?: boolean;
  invalid?: boolean;
  /** Prefills Fetch's host: a hostname, or a URL whose hostname is used. */
  host?: string;
  /** Prefills Fetch's port; defaults to 22. */
  port?: number;
  /** Without one, only paste is offered. */
  scope?: HostKeyScope;
};

const PEEK_DENIED = 'Needs the delivery:write permission';

function hostOf(v: string | undefined): string {
  const s = (v ?? '').trim();
  if (!s.includes('://')) return s;
  try {
    return new URL(s).hostname;
  } catch {
    return s;
  }
}

/** An SSH host key line with Fetch from server (the key the host presents). */
export function HostKeyInput({ id, value, onChange, label = 'Host key', disabled, invalid, host, port, scope }: Props) {
  const [open, setOpen] = useState(false);
  return (
    <div className="grid min-w-0 gap-1.5">
      <Input
        id={id}
        className="font-mono text-xs"
        spellCheck={false}
        value={value}
        disabled={disabled}
        aria-invalid={invalid || undefined}
        onChange={(e) => onChange(e.target.value)}
      />
      {!disabled && scope && (
        <div className="flex flex-wrap items-center gap-1.5">
          <PermissionTip allowed={scope.canPeek} action="delivery:write" reason={PEEK_DENIED}>
            {scope.canPeek ? (
              <Tooltip>
                <TooltipTrigger asChild>
                  <Button type="button" variant="outline" size="sm" onClick={() => setOpen(true)}>
                    <Globe aria-hidden /> Fetch from server
                  </Button>
                </TooltipTrigger>
                <TooltipContent className="max-w-64">{help['hostKey.fetch'].text}</TooltipContent>
              </Tooltip>
            ) : (
              <Button type="button" variant="outline" size="sm" disabled>
                <Globe aria-hidden /> Fetch from server
              </Button>
            )}
          </PermissionTip>
        </div>
      )}
      {scope?.canPeek && open && (
        <FetchKeyDialog
          orgId={scope.orgId}
          host={hostOf(host)}
          port={port}
          label={label}
          onClose={() => setOpen(false)}
          onUse={(key) => {
            onChange(key);
            setOpen(false);
          }}
        />
      )}
    </div>
  );
}

function FetchKeyDialog({ orgId, host, port, label, onClose, onUse }: { orgId: string; host: string; port?: number; label: string; onClose: () => void; onUse: (key: string) => void }) {
  const peek = usePeekSshHostKey(orgId);
  const [h, setH] = useState(host);
  const [p, setP] = useState(String(port ?? 22));
  const [picked, setPicked] = useState('');
  const result = peek.isSuccess ? peek.data : undefined;
  const keys: SshPeekHostKey[] = result?.ok ? result.keys : [];
  const error = peek.isError ? errorMessage(peek.error) : result && !result.ok ? result.error || 'Could not read the host key.' : undefined;
  const portNum = Number(p);
  const portOk = p.trim() === '' || (Number.isInteger(portNum) && portNum >= 1 && portNum <= 65535);

  const run = () => {
    if (h.trim() === '' || !portOk) return;
    setPicked('');
    const body = { host: h.trim(), ...(p.trim() !== '' ? { port: portNum } : {}) };
    peek.mutate(body, {
      onSuccess: (r) => setPicked(r.ok ? (r.keys.find((k) => k.type === 'ssh-ed25519') ?? r.keys[0])?.key ?? '' : ''),
    });
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-h-[90dvh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-1.5">
            Fetch from server <HelpTip id="hostKey.tofu" warning />
          </DialogTitle>
          <DialogDescription className="sr-only">Read the {label.toLowerCase()} a server presents and pick the one to pin.</DialogDescription>
        </DialogHeader>
        <form
          className="flex min-w-0 gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            e.stopPropagation();
            run();
          }}
        >
          <Input aria-label="Host" className="min-w-0 flex-1 font-mono text-xs" value={h} onChange={(e) => setH(e.target.value)} placeholder="router.lan" autoFocus />
          <Input aria-label="Port" className="w-20 font-mono text-xs" inputMode="numeric" value={p} onChange={(e) => setP(e.target.value)} aria-invalid={!portOk || undefined} />
          <Button type="submit" variant="outline" disabled={h.trim() === '' || !portOk || peek.isPending}>
            {peek.isPending && <LoaderCircle className="animate-spin" aria-hidden />}
            Fetch
          </Button>
        </form>
        {error && (
          <p role="alert" className="flex items-start gap-1 text-xs">
            <CircleAlert className="mt-px size-3.5 shrink-0 text-failed" aria-hidden />
            <span className="min-w-0 break-words">{error}</span>
          </p>
        )}
        {keys.length > 0 && (
          <ToggleGroup.Root
            type="single"
            value={picked}
            onValueChange={(v) => v && setPicked(v)}
            aria-label="Host keys"
            className="grid gap-2"
          >
            {keys.map((k) => {
              const on = picked === k.key;
              return (
                <ToggleGroup.Item
                  key={k.key}
                  value={k.key}
                  className={cn(
                    'grid min-w-0 gap-0.5 rounded-md border p-2.5 text-left text-xs transition-colors',
                    on ? 'border-primary bg-selected' : 'border-border bg-panel hover:bg-subtle',
                  )}
                >
                  <span className="flex min-w-0 items-center gap-1.5">
                    <span className={cn('flex size-4 shrink-0 items-center justify-center rounded-full border', on ? 'border-primary bg-primary text-on-primary' : 'border-border')}>
                      {on && <Check className="size-3" aria-hidden />}
                    </span>
                    <span className="min-w-0 truncate text-sm font-medium">{k.type}</span>
                  </span>
                  <span className="font-mono text-[11px] break-all text-ink-muted">{k.sha256}</span>
                </ToggleGroup.Item>
              );
            })}
          </ToggleGroup.Root>
        )}
        <DialogFooter>
          <Button type="button" variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button type="button" disabled={picked === ''} onClick={() => onUse(picked)}>
            Use key
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
