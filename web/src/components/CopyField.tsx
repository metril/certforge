import { useEffect, useState } from 'react';
import { Check, Copy, TriangleAlert } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

type Status = 'idle' | 'copied' | 'failed';

export function CopyField({ value, label, display, className }: { value: string; label: string; display?: string; className?: string }) {
  const [status, setStatus] = useState<Status>('idle');
  useEffect(() => {
    if (status === 'idle') return;
    const t = window.setTimeout(() => setStatus('idle'), 1500);
    return () => window.clearTimeout(t);
  }, [status]);
  return (
    <span className={cn('inline-flex min-w-0 items-center gap-1', className)}>
      <code className="truncate font-mono text-xs" title={value}>
        {display ?? value}
      </code>
      <Button
        type="button"
        variant="ghost"
        size="icon"
        className="size-7 shrink-0"
        aria-label={`Copy ${label}`}
        onClick={async (e) => {
          e.stopPropagation();
          // A LAN deployment reachable over plain http, or a browser that
          // simply refuses the request, both leave navigator.clipboard
          // missing or writeText rejecting; either must surface as a
          // visible failure, not an unhandled rejection (review round 1).
          try {
            if (!navigator.clipboard) throw new Error('Clipboard API unavailable');
            await navigator.clipboard.writeText(value);
            setStatus('copied');
          } catch {
            setStatus('failed');
          }
        }}
      >
        {status === 'copied' && <Check className="size-3.5 text-valid" aria-hidden />}
        {status === 'failed' && <TriangleAlert className="size-3.5 text-failed" aria-hidden />}
        {status === 'idle' && <Copy className="size-3.5" aria-hidden />}
      </Button>
      <span aria-live="polite" className="sr-only">
        {status === 'copied' && 'Copied'}
        {status === 'failed' && 'Copy failed'}
      </span>
    </span>
  );
}
