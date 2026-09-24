import { useState } from 'react';
import { KeyRound } from 'lucide-react';
import type { DnsCredential, ProviderSchema } from '@/api/types';
import { CommandDialog, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from '@/components/ui/command';
import { Tooltip, TooltipContent, TooltipTrigger } from '@/components/ui/tooltip';
import { pushRecent, readRecent } from '@/lib/recent';

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
  // and carry their reason as a tooltip; `disabled` on CommandItem also
  // drops them from cmdk's own arrow-key navigation, so they are never
  // selectable by keyboard either.
  const item = (section: string, p: ProviderSchema) => {
    const { unsupported, reason } = unsupportedFlags(p);
    const el = (
      <CommandItem
        key={`${section}:${p.code}`}
        value={`${section}:${p.code}`}
        keywords={[p.name, p.code, ...(p.aliases ?? [])]}
        disabled={unsupported}
        onSelect={() => pick(p)}
      >
        <span>{p.name}</span>
        <span className="ml-auto font-mono text-xs text-ink-muted">{p.code}</span>
      </CommandItem>
    );
    if (!unsupported) return el;
    return (
      <Tooltip key={`${section}:${p.code}`}>
        <TooltipTrigger asChild>
          <span tabIndex={0}>{el}</span>
        </TooltipTrigger>
        <TooltipContent>{reason}</TooltipContent>
      </Tooltip>
    );
  };

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange} title="Choose DNS provider" description="Search by name, code, or alias">
      <CommandInput placeholder="cloudflare" value={search} onValueChange={setSearch} />
      <CommandList>
        <CommandEmpty>No provider matches.</CommandEmpty>
        {onPickCredential && credentials.length > 0 && (
          <CommandGroup heading="Credentials in this org">
            {credentials.map((c) => (
              <CommandItem
                key={c.id}
                value={`cred:${c.id}`}
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
