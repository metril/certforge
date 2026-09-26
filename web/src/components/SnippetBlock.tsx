import { Check, Copy, TriangleAlert } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useCopy } from '@/lib/useCopy';

/** A multi-line machine value (shell command, compose file) with a copy
 * button. It scrolls inside its own box, so the page never scrolls sideways. */
export function SnippetBlock({ value, label }: { value: string; label: string }) {
  const { status, copy } = useCopy(value);
  return (
    <div className="relative min-w-0 rounded-md border border-border bg-subtle">
      <pre aria-label={label} tabIndex={0} className="max-h-64 overflow-auto whitespace-pre p-3 pr-11 font-mono text-xs leading-5">
        {value}
      </pre>
      <Button type="button" variant="ghost" size="icon" className="absolute right-1 top-1 size-7" aria-label={`Copy ${label}`} onClick={() => void copy()}>
        {status === 'copied' && <Check className="size-3.5 text-valid" aria-hidden />}
        {status === 'failed' && <TriangleAlert className="size-3.5 text-failed" aria-hidden />}
        {status === 'idle' && <Copy className="size-3.5" aria-hidden />}
      </Button>
      <span aria-live="polite" className="sr-only">
        {status === 'copied' && 'Copied'}
        {status === 'failed' && 'Copy failed'}
      </span>
    </div>
  );
}
