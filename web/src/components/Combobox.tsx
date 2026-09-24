import { useState, type ReactNode } from 'react';
import { Check, ChevronsUpDown } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import { cn } from '@/lib/utils';

export type ComboOption = { value: string; label: string; hint?: string; keywords?: string[] };

type Props = {
  id?: string;
  value: string | undefined;
  onChange: (value: string) => void;
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
          className={cn('h-9 w-full justify-between font-normal', mono && 'font-mono text-xs')}
        >
          {selected ? <span className="truncate">{selected.label}</span> : <span className="text-ink-muted">{placeholder}</span>}
          <ChevronsUpDown className="size-4 shrink-0 text-ink-muted" aria-hidden />
        </Button>
      </PopoverTrigger>
      <PopoverContent align="start" className="w-(--radix-popover-trigger-width) min-w-64 p-0">
        <Command>
          <CommandInput placeholder="Search" />
          <CommandList>
            <CommandEmpty>{emptyText}</CommandEmpty>
            <CommandGroup>
              {options.map((o) => (
                <CommandItem
                  key={o.value}
                  value={o.value}
                  keywords={[o.label, ...(o.keywords ?? [])]}
                  onSelect={() => {
                    onChange(o.value);
                    setOpen(false);
                  }}
                >
                  <Check className={cn('size-4', o.value === value ? 'opacity-100' : 'opacity-0')} aria-hidden />
                  <span className={cn('truncate', mono && 'font-mono text-xs')}>{o.label}</span>
                  {o.hint && <span className="ml-auto truncate text-xs text-ink-muted">{o.hint}</span>}
                </CommandItem>
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
  );
}
