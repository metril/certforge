import { X } from 'lucide-react';
import { IconButton } from '@/components/IconButton';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

export function FilterChips({ chips, onRemove, onClear, className }: { chips: { key: string; label: string }[]; onRemove: (key: string) => void; onClear: () => void; className?: string }) {
  if (chips.length === 0) return null;
  return (
    <div className={cn('flex flex-wrap items-center gap-1.5', className)}>
      {chips.map((c) => (
        <span key={c.key} className="inline-flex h-7 items-center gap-1 rounded-sm border border-primary/40 bg-primary/8 pl-2.5 pr-1 text-sm">
          {c.label}
          <IconButton type="button" variant="ghost" size="icon-xs" label={`Remove filter ${c.label}`} onClick={() => onRemove(c.key)} className="size-auto rounded-sm p-0.5 hover:bg-primary/15">
            <X className="size-3.5" aria-hidden />
          </IconButton>
        </span>
      ))}
      <Button variant="link" size="sm" onClick={onClear}>
        Clear all
      </Button>
    </div>
  );
}
