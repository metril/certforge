import type { ReactNode } from 'react';
import { Check } from 'lucide-react';
import { ToggleGroup } from 'radix-ui';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

export type ChipOption<T extends string> = { value: T; label: ReactNode; disabled?: boolean; hint?: string };

type Props<T extends string> = { value: T[]; onChange: (v: T[]) => void; options: ChipOption<T>[]; 'aria-label': string; id?: string };

export function ChipSet<T extends string>({ value, onChange, options, id, ...rest }: Props<T>) {
  return (
    <ToggleGroup.Root
      id={id}
      type="multiple"
      value={value}
      onValueChange={(v) => onChange(v as T[])}
      aria-label={rest['aria-label']}
      className="flex flex-wrap gap-1.5"
    >
      {options.map((o) => {
        const on = value.includes(o.value);
        const chip = (
          <ToggleGroup.Item
            key={o.value}
            value={o.value}
            disabled={o.disabled}
            className={cn(
              'inline-flex h-7 items-center gap-1 rounded-sm border px-2.5 text-sm transition-colors',
              on ? 'border-primary bg-primary text-on-primary' : 'border-border bg-panel text-ink hover:bg-subtle',
              'disabled:cursor-not-allowed disabled:opacity-50',
            )}
          >
            {on && <Check data-testid="chip-check" className="size-3.5" aria-hidden />}
            {o.label}
          </ToggleGroup.Item>
        );
        if (!o.hint) return chip;
        return (
          <Tooltip key={o.value}>
            <TooltipTrigger asChild>
              <span tabIndex={o.disabled ? 0 : -1}>{chip}</span>
            </TooltipTrigger>
            <TooltipContent>{o.hint}</TooltipContent>
          </Tooltip>
        );
      })}
    </ToggleGroup.Root>
  );
}
