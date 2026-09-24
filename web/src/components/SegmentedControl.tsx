import type { ReactNode } from 'react';
import { ToggleGroup } from 'radix-ui';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn } from '@/lib/utils';

export type SegmentOption<T extends string> = { value: T; label: ReactNode; disabled?: boolean; hint?: string };

type Props<T extends string> = {
  value: T;
  onChange: (value: T) => void;
  options: SegmentOption<T>[];
  'aria-label': string;
  id?: string;
  size?: 'sm' | 'md';
};

export function SegmentedControl<T extends string>({ value, onChange, options, id, size = 'md', ...rest }: Props<T>) {
  return (
    <ToggleGroup.Root
      id={id}
      type="single"
      value={value}
      onValueChange={(v) => {
        if (v) onChange(v as T);
      }}
      aria-label={rest['aria-label']}
      className={cn('inline-flex w-fit items-center gap-0.5 rounded-md border border-border bg-subtle p-0.5', size === 'sm' ? 'h-7' : 'h-9')}
    >
      {options.map((o) => {
        const item = (
          <ToggleGroup.Item
            key={o.value}
            value={o.value}
            disabled={o.disabled}
            className={cn(
              'inline-flex h-full items-center gap-1.5 rounded-sm px-3 text-sm text-ink-muted transition-colors',
              'hover:text-ink disabled:cursor-not-allowed disabled:opacity-50',
              'data-[state=on]:bg-panel data-[state=on]:font-semibold data-[state=on]:text-ink data-[state=on]:ring-1 data-[state=on]:ring-border',
            )}
          >
            {o.label}
          </ToggleGroup.Item>
        );
        if (!o.hint) return item;
        return (
          <Tooltip key={o.value}>
            <TooltipTrigger asChild>
              <span tabIndex={o.disabled ? 0 : -1} className="h-full">
                {item}
              </span>
            </TooltipTrigger>
            <TooltipContent>{o.hint}</TooltipContent>
          </Tooltip>
        );
      })}
    </ToggleGroup.Root>
  );
}
