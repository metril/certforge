import { useState } from 'react';
import { Check, ChevronsUpDown, X } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { cn, keywordFilter } from '@/lib/utils';
import { OptionWithHint, type ComboOption } from './Combobox';

type Props = {
  id?: string;
  value: string[];
  onChange: (value: string[]) => void;
  options: ComboOption[];
  placeholder: string;
  emptyText: string;
  disabled?: boolean;
  /** Overrides the trigger text (default "N selected"). */
  triggerLabel?: (value: string[], labelOf: (v: string) => string) => string;
  /** Hide the removable chips under the trigger (for compact toolbars). */
  hideChips?: boolean;
  'aria-label': string;
};

/** design.md Controls: "multi-lookups render selected items as removable
 * chips". The popover stays open while picking; selection order is kept. */
export function MultiCombobox({ id, value, onChange, options, placeholder, emptyText, disabled, triggerLabel, hideChips, ...rest }: Props) {
  const [open, setOpen] = useState(false);
  const labelOf = (v: string) => options.find((o) => o.value === v)?.label ?? v;
  const groups: { label?: string; options: ComboOption[] }[] = [];
  for (const o of options) {
    const last = groups[groups.length - 1];
    if (last && last.label === o.group) last.options.push(o);
    else groups.push({ label: o.group, options: [o] });
  }
  const toggle = (v: string) => onChange(value.includes(v) ? value.filter((x) => x !== v) : [...value, v]);
  return (
    <div className="grid min-w-0 gap-2">
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
            className="h-9 min-w-0 justify-between bg-field font-normal hover:border-ink-muted hover:bg-field focus-visible:border-primary focus-visible:ring-2 focus-visible:ring-ring/40"
          >
            <span className={cn('truncate', value.length === 0 && 'text-ink-muted')}>{value.length ? (triggerLabel ? triggerLabel(value, labelOf) : `${value.length} selected`) : placeholder}</span>
            <ChevronsUpDown className="size-4 shrink-0 text-ink-muted" aria-hidden />
          </Button>
        </PopoverTrigger>
        <PopoverContent align="start" className="w-(--radix-popover-trigger-width) min-w-64 p-0">
          <Command filter={keywordFilter}>
            <CommandInput placeholder="Search" />
            <CommandList>
              <CommandEmpty>{emptyText}</CommandEmpty>
              {groups.map((g, gi) => (
                <CommandGroup key={gi} heading={g.label}>
                {g.options.map((o) => (
                  <OptionWithHint key={o.value} disabled={o.disabled} hint={o.hint}>
                    <CommandItem
                      value={o.value}
                      disabled={o.disabled}
                      keywords={[o.label, ...(o.keywords ?? [])]}
                      onSelect={() => {
                        if (o.disabled) return;
                        toggle(o.value);
                      }}
                    >
                      <Check className={cn('size-4', value.includes(o.value) ? 'opacity-100' : 'opacity-0')} aria-hidden />
                      <span className="truncate">{o.label}</span>
                      {o.hint && !o.disabled && <span className="ml-auto truncate text-xs text-ink-muted">{o.hint}</span>}
                    </CommandItem>
                  </OptionWithHint>
                ))}
                </CommandGroup>
              ))}
            </CommandList>
          </Command>
        </PopoverContent>
      </Popover>
      {!hideChips && value.length > 0 && (
        <ul aria-label={`Selected ${rest['aria-label'].toLowerCase()}`} className="flex flex-wrap gap-1.5">
          {value.map((v) => (
            <li key={v} className="inline-flex h-7 items-center gap-1 rounded-sm border border-primary bg-primary pl-2 pr-0.5 text-sm text-on-primary">
              <Check className="size-3.5" aria-hidden />
              <span className="max-w-48 truncate">{labelOf(v)}</span>
              <button
                type="button"
                aria-label={`Remove ${labelOf(v)}`}
                disabled={disabled}
                className="inline-flex size-6 items-center justify-center rounded-sm hover:bg-on-primary/20"
                onClick={() => onChange(value.filter((x) => x !== v))}
              >
                <X className="size-3.5" aria-hidden />
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
