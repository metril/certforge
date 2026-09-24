import { Check } from 'lucide-react';
import { cn } from '@/lib/utils';

type Props = { steps: string[]; current: number; onSelect?: (i: number) => void; canSelect?: (i: number) => boolean };

export function Stepper({ steps, current, onSelect, canSelect = (i) => i <= current }: Props) {
  return (
    <ol className="flex flex-wrap items-center gap-x-5 gap-y-2" aria-label="Steps">
      {steps.map((label, i) => {
        const done = i < current;
        const active = i === current;
        const enabled = !!onSelect && canSelect(i) && !active;
        return (
          <li key={label} className="flex items-center gap-2">
            <button
              type="button"
              disabled={!enabled}
              aria-current={active ? 'step' : undefined}
              onClick={() => onSelect?.(i)}
              className={cn('inline-flex items-center gap-2 rounded-md text-sm', active ? 'font-semibold text-ink' : 'text-ink-muted', enabled && 'hover:text-ink')}
            >
              <span
                className={cn(
                  'inline-flex size-6 items-center justify-center rounded-full border text-xs',
                  active && 'border-primary bg-primary text-on-primary',
                  done && 'border-primary text-primary',
                  !active && !done && 'border-border',
                )}
              >
                {done ? <Check className="size-3.5" aria-hidden /> : i + 1}
              </span>
              {label}
            </button>
          </li>
        );
      })}
    </ol>
  );
}
