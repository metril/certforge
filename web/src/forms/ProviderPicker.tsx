import { useEffect, useState } from 'react';
import { CircleAlert, KeyRound } from 'lucide-react';
import type { DnsCredential, ProviderSchema } from '@/api/types';
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { pushRecent, readRecent } from '@/lib/recent';
import { keywordFilter } from '@/lib/utils';

export const COMMON_PROVIDERS = ['cloudflare', 'route53', 'azuredns', 'gcloud', 'digitalocean', 'ovh', 'hetzner', 'gandiv5', 'porkbun'];

type Props = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  providers: ProviderSchema[];
  credentials?: DnsCredential[];
  onPickProvider: (p: ProviderSchema) => void;
  onPickCredential?: (c: DnsCredential) => void;
};

// Provider flags (preflight A10) live inside `schema` itself, not as
// top-level SchemaEntry fields; `schema` is typed as a bag of unknown
// (api/types.ts ProviderSchema = SchemaEntry), so read them defensively.
function unsupportedFlags(p: ProviderSchema): { unsupported: boolean; reason?: string } {
  const s = p.schema as { unsupported?: boolean; unsupportedReason?: string } | undefined;
  return { unsupported: s?.unsupported === true, reason: s?.unsupportedReason };
}

export function ProviderPicker({ open, onOpenChange, providers, credentials = [], onPickProvider, onPickCredential }: Props) {
  const [search, setSearch] = useState('');
  // Fix round 1: a stray search left over from the last time the dialog was
  // open otherwise persists (this component, and the `search` state it
  // owns, stays mounted across open/close — only the dialog's own content
  // unmounts), so reopening showed a filtered list until the caller retyped.
  useEffect(() => {
    if (!open) setSearch('');
  }, [open]);

  const byCode = new Map(providers.map((p) => [p.code, p]));
  const recent = readRecent()
    .map((c) => byCode.get(c))
    .filter((p): p is ProviderSchema => !!p);
  const common = COMMON_PROVIDERS.map((c) => byCode.get(c)).filter((p): p is ProviderSchema => !!p);
  const all = [...providers].sort((a, b) => a.name.localeCompare(b.name));
  const searching = search.trim() !== '';

  const pick = (p: ProviderSchema) => {
    pushRecent(p.code);
    onPickProvider(p);
    onOpenChange(false);
  };

  // Unsupported providers (schema.unsupported, preflight A10) are disabled
  // and carry their reason as a tooltip on a small icon inside the item
  // (not a wrapper around the whole item: a wrapper would add a focusable
  // node that isn't itself an `option` inside the listbox, and would linger
  // in the DOM — with its own tabIndex — even once cmdk's own filtering
  // hides the CommandItem it wraps, since only that inner element reacts to
  // the search text). `disabled` on CommandItem also drops it from cmdk's
  // own arrow-key navigation, so it is never selectable by keyboard either;
  // the icon stays a plain sibling button, reachable by Tab regardless, and
  // `pointer-events-auto` overrides the item's own disabled
  // `pointer-events-none` so it's still hoverable.
  const item = (section: string, p: ProviderSchema) => {
    const { unsupported, reason } = unsupportedFlags(p);
    return (
      <CommandItem
        key={`${section}:${p.code}`}
        value={p.name}
        keywords={[p.name, p.code, ...(p.aliases ?? [])]}
        disabled={unsupported}
        onSelect={() => pick(p)}
      >
        <span>{p.name}</span>
        {unsupported && (
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                type="button"
                aria-label={`Why ${p.name} is unavailable`}
                className="pointer-events-auto rounded-sm text-ink-muted hover:text-ink"
                onClick={(e) => e.stopPropagation()}
              >
                <CircleAlert className="size-3.5" aria-hidden />
              </button>
            </TooltipTrigger>
            <TooltipContent>{reason}</TooltipContent>
          </Tooltip>
        )}
        <span className="ml-auto font-mono text-xs text-ink-muted">{p.code}</span>
      </CommandItem>
    );
  };

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      title="Choose DNS provider"
      description="Search by name, code, or alias"
      commandProps={{ filter: keywordFilter }}
    >
      <CommandInput placeholder="cloudflare" value={search} onValueChange={setSearch} />
      <CommandList>
        <CommandEmpty>No provider matches.</CommandEmpty>
        {onPickCredential && credentials.length > 0 && (
          <CommandGroup heading="Credentials in this org">
            {credentials.map((c) => (
              <CommandItem
                key={c.id}
                value={c.name}
                keywords={[c.name, c.providerCode, byCode.get(c.providerCode)?.name ?? '']}
                onSelect={() => {
                  onPickCredential(c);
                  onOpenChange(false);
                }}
              >
                <KeyRound className="size-4 text-ink-muted" aria-hidden />
                <span>{c.name}</span>
                <span className="ml-auto text-xs text-ink-muted">{byCode.get(c.providerCode)?.name ?? c.providerCode}</span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
        {!searching && recent.length > 0 && <CommandGroup heading="Recently used">{recent.map((p) => item('recent', p))}</CommandGroup>}
        {!searching && common.length > 0 && <CommandGroup heading="Common">{common.map((p) => item('common', p))}</CommandGroup>}
        <CommandGroup heading="All providers">{all.map((p) => item('all', p))}</CommandGroup>
      </CommandList>
    </CommandDialog>
  );
}
