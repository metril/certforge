import type { ReactNode } from 'react';
import { CircleAlert, CircleCheck } from 'lucide-react';
import type { Client, DnsCredential } from '@/api/types';
import { HelpTip } from '@/components/HelpTip';
import { SourceBadge } from '@/forms/InheritableField';
import { isCovered, type Coverage } from '@/lib/coverage';
import { METHOD_LABEL, ruleTarget } from '@/lib/rules';

// Fix round 1 (review, item 4): "(via apex)" marks a wildcard whose apex is
// also on the certificate — the router strips "*." before routing, so the
// two names share the apex's rule (see coverage()'s viaApex).
function suffix(c: Coverage): ReactNode {
  return c.viaApex ? ' (via apex)' : null;
}

function describe(c: Coverage, creds: DnsCredential[], clients: Client[]): ReactNode {
  switch (c.state) {
    case 'rule': {
      const rule = c.rule!;
      return (
        <>
          Rule {c.ruleIndex! + 1}: {rule.match} → {METHOD_LABEL[rule.method]} · {ruleTarget(rule, creds, clients)}
          {suffix(c)}
        </>
      );
    }
    case 'inherited':
      return (
        <>
          Catch-all: inherited from <SourceBadge source={c.source!} />
          {suffix(c)}
        </>
      );
    case 'incomplete': {
      // Fix round 1 (review, item 4): distinguish a certificate's own rule
      // missing a credential/client from an inherited one — otherwise the
      // user looks for a rule of their own that doesn't exist.
      const missing = c.rule!.method === 'dns-01' ? 'credential' : 'client';
      return c.source ? (
        <>
          Inherited rule (<SourceBadge source={c.source} />): no {missing}
          {suffix(c)}
        </>
      ) : (
        <>
          No {missing}
          {suffix(c)}
        </>
      );
    }
    case 'wildcard-non-dns':
      return 'Wildcards need a DNS method';
    case 'ip':
      return "IP names aren't supported";
    case 'none':
      return (
        <>
          No matching rule
          {suffix(c)}
        </>
      );
  }
}

export function CoveragePanel({ items, credentials, clients }: { items: Coverage[]; credentials: DnsCredential[]; clients: Client[] }) {
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
            <span className="flex items-center gap-1 truncate text-ink-muted">{describe(c, credentials, clients)}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}
