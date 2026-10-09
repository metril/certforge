import { Check, Copy, TriangleAlert } from 'lucide-react';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';
import { useCopy } from '@/lib/useCopy';
import { IconButton } from '@/components/IconButton';

export function CopyField({ value, label, display, className }: { value: string; label: string; display?: string; className?: string }) {
  const { status, copy } = useCopy(value);
  return (
    <span className={cn('inline-flex max-w-full min-w-0 items-center gap-1', className)}>
      <Tooltip>
        <TooltipTrigger asChild>
          {/* Fix round 1 (#2): `truncate` alone doesn't shrink a flex item
              below its content's intrinsic width — it also needs `min-w-0`
              on the element itself, not just the row it sits in. The full
              value (not just the visible/truncated text) shows on hover. */}
          <code tabIndex={0} className="min-w-0 truncate font-mono text-xs">
            {display ?? value}
          </code>
        </TooltipTrigger>
        <TooltipContent side="top" className="max-w-80 break-all font-mono text-xs">
          {value}
        </TooltipContent>
      </Tooltip>
      <IconButton
        type="button"
        variant="ghost"
        size="icon"
        className="size-7 shrink-0"
        label={`Copy ${label}`}
        onClick={(e) => {
          e.stopPropagation();
          void copy();
        }}
      >
        {status === 'copied' && <Check className="size-3.5 text-valid" aria-hidden />}
        {status === 'failed' && <TriangleAlert className="size-3.5 text-failed" aria-hidden />}
        {status === 'idle' && <Copy className="size-3.5" aria-hidden />}
      </IconButton>
      <span aria-live="polite" className="sr-only">
        {status === 'copied' && 'Copied'}
        {status === 'failed' && 'Copy failed'}
      </span>
    </span>
  );
}
