import { useEffect, useState } from 'react';
import { Check, Copy } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

export function CopyField({ value, label, display, className }: { value: string; label: string; display?: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = window.setTimeout(() => setCopied(false), 1500);
    return () => window.clearTimeout(t);
  }, [copied]);
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
          await navigator.clipboard.writeText(value);
          setCopied(true);
        }}
      >
        {copied ? <Check className="size-3.5 text-valid" aria-hidden /> : <Copy className="size-3.5" aria-hidden />}
      </Button>
      <span aria-live="polite" className="sr-only">
        {copied ? 'Copied' : ''}
      </span>
    </span>
  );
}
