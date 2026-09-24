import type { ReactNode } from 'react';
import { CircleAlert, CircleCheck } from 'lucide-react';
import type { DnsCredential } from '@/api/types';
import { HelpTip } from '@/components/HelpTip';
import { SourceBadge } from '@/forms/InheritableField';
import { isCovered, type Coverage } from '@/lib/coverage';

function describe(c: Coverage, credName: (id?: string) => string | undefined): ReactNode {
  switch (c.state) {
    case 'rule': {
      const target = c.rule!.method === 'manual-dns' ? 'manual' : (credName(c.rule!.dnsCredentialId) ?? 'credential');
      return `Rule ${c.ruleIndex! + 1}: ${c.rule!.match} → ${target}`;
    }
    case 'inherited':
      return (
        <>
          Catch-all: inherited from <SourceBadge source={c.source!} />
        </>
      );
    case 'missing-credential':
      return 'No credential';
    case 'ip':
      return 'IP names need HTTP-01 (later phase)';
    case 'none':
      return 'No matching rule';
  }
}

export function CoveragePanel({ items, credentials }: { items: Coverage[]; credentials: DnsCredential[] }) {
  const credName = (id?: string) => credentials.find((c) => c.id === id)?.name;
  return (
    <section aria-label="Coverage" className="grid gap-2">
      <h3 className="flex items-center gap-1.5 text-sm font-semibold">
        Coverage <HelpTip id="rules.coverage" />
      </h3>
      <ul className="grid">
        {items.map((c) => (
          <li key={c.name} className="flex min-h-8 flex-wrap items-center gap-2 border-b border-border py-1 text-sm last:border-b-0">
            {isCovered(c) ? <CircleCheck className="size-4 shrink-0 text-valid" aria-hidden /> : <CircleAlert className="size-4 shrink-0 text-expiring" aria-hidden />}
            <span className="min-w-0 flex-1 truncate font-mono text-xs">{c.name}</span>
            <span className="flex items-center gap-1 truncate text-ink-muted">{describe(c, credName)}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
