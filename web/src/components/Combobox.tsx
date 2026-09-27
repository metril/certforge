import { useState, type ReactNode } from 'react';
import { Check, ChevronsUpDown, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn, keywordFilter } from '@/lib/utils';

export type ComboOption = { value: string; label: string; hint?: string; keywords?: string[]; disabled?: boolean };

type Props = {
  id?: string;
  value: string | undefined;
  /** Called with an option's value on select, or `undefined` when the clear action is used (optional lookups). */
  onChange: (value: string | undefined) => void;
  options: ComboOption[];
  placeholder: string;
  emptyText: string;
  footer?: ReactNode;
  disabled?: boolean;
  mono?: boolean;
  'aria-label'?: string;
};

export function Combobox({ id, value, onChange, options, placeholder, emptyText, footer, disabled, mono, ...rest }: Props) {
  const [open, setOpen] = useState(false);
  const selected = options.find((o) => o.value === value);
  return (
    <div className="flex items-center gap-1">
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <Button
            id={id}
            type="button"
            variant="outline"
            role="combobox"
            aria-expanded={open}
            aria-label={rest['aria-label']}
            disabled={disabled}
            className={cn('h-9 min-w-0 flex-1 justify-between font-normal', mono && 'font-mono text-xs')}
          >
            {selected ? <span className="truncate">{selected.label}</span> : <span className="text-ink-muted">{placeholder}</span>}
            <ChevronsUpDown className="size-4 shrink-0 text-ink-muted" aria-hidden />
          </Button>
        </PopoverTrigger>
        <PopoverContent align="start" className="w-(--radix-popover-trigger-width) min-w-64 p-0">
          <Command filter={keywordFilter}>
            <CommandInput placeholder="Search" />
            <CommandList>
              <CommandEmpty>{emptyText}</CommandEmpty>
              <CommandGroup>
                {options.map((o) => {
                  const item = (
                    <CommandItem
                      key={o.value}
                      value={o.value}
                      disabled={o.disabled}
                      keywords={[o.label, ...(o.keywords ?? [])]}
                      onSelect={() => {
                        if (o.disabled) return;
                        onChange(o.value);
                        setOpen(false);
                      }}
                    >
                      <Check className={cn('size-4', o.value === value ? 'opacity-100' : 'opacity-0')} aria-hidden />
                      <span className={cn('truncate', mono && 'font-mono text-xs')}>{o.label}</span>
                      {o.hint && !o.disabled && <span className="ml-auto truncate text-xs text-ink-muted">{o.hint}</span>}
                    </CommandItem>
                  );
                  if (!o.disabled || !o.hint) return item;
                  return (
                    <Tooltip key={o.value}>
                      <TooltipTrigger asChild>
                        <span tabIndex={0}>{item}</span>
                      </TooltipTrigger>
                      <TooltipContent>{o.hint}</TooltipContent>
                    </Tooltip>
                  );
                })}
              </CommandGroup>
            </CommandList>
            {footer && (
              <div className="border-t border-border p-1" onClick={() => setOpen(false)}>
                {footer}
              </div>
            )}
          </Command>
        </PopoverContent>
      </Popover>
      {selected && !disabled && (
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          className="shrink-0"
          aria-label={`Clear ${rest['aria-label'] ?? placeholder}`}
          onClick={() => onChange(undefined)}
        >
          <X className="size-4" aria-hidden />
        </Button>
      )}
    </div>
  );
}
