import { useState, type ReactElement, type ReactNode } from 'react';
import { Check, ChevronsUpDown, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { cn, keywordFilter } from '@/lib/utils';
import { IconButton } from '@/components/IconButton';

export type ComboOption = { value: string; label: string; hint?: string; keywords?: string[]; disabled?: boolean; /** MultiCombobox only: options sharing a group render under one heading. */ group?: string };

/** Shared by Combobox and MultiCombobox (B4): a disabled option with a
 * `hint` gets a Tooltip showing it (the same wrap-in-a-tabbable-span
 * pattern ChipSet/SegmentedControl already use for a disabled option with a
 * reason); anything else renders as is. */
export function OptionWithHint({ disabled, hint, children }: { disabled?: boolean; hint?: string; children: ReactElement }): ReactNode {
  if (!disabled || !hint) return children;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span>{children}</span>
      </TooltipTrigger>
      <TooltipContent>{hint}</TooltipContent>
    </Tooltip>
  );
}

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
  /** Show the trailing clear button when a value is picked (default true). */
  clearable?: boolean;
  'aria-label'?: string;
};

export function Combobox({ id, value, onChange, options, placeholder, emptyText, footer, disabled, mono, clearable = true, ...rest }: Props) {
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
            className={cn('h-9 min-w-0 flex-1 justify-between bg-field font-normal hover:border-ink-muted hover:bg-field focus-visible:border-primary focus-visible:ring-2 focus-visible:ring-ring/40', mono && 'font-mono text-xs')}
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
                {options.map((o) => (
                  <OptionWithHint key={o.value} disabled={o.disabled} hint={o.hint}>
                    <CommandItem
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
                  </OptionWithHint>
                ))}
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
      {clearable && selected && !disabled && (
        <IconButton
          type="button"
          variant="ghost"
          size="icon-sm"
          className="shrink-0"
          label={`Clear ${rest['aria-label'] ?? placeholder}`}
          onClick={() => onChange(undefined)}
        >
          <X className="size-4" aria-hidden />
        </IconButton>
      )}
    </div>
  );
}
