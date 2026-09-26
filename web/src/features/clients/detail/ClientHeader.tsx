import type { ReactNode } from 'react';
import { Clock } from 'lucide-react';
import type { Client } from '@/api/types';
import { ConnectionDot } from '@/components/ConnectionDot';
import { HelpTip } from '@/components/HelpTip';
import { ToneChip } from '@/components/StatusChip';
import { agentCertExpiring, headerConnectionLabel } from '@/lib/clientStatus';
import type { HelpKey } from '@/lib/help';
import { fmtDateTime, relDays } from '@/lib/time';

function Fact({ label, help, children }: { label: string; help?: HelpKey; children: ReactNode }) {
  return (
    <div className="grid min-w-0 gap-0.5">
      <dt className="flex items-center gap-1.5 text-xs text-ink-muted">
        {label}
        {help && <HelpTip id={help} />}
      </dt>
      <dd className="min-w-0 truncate">{children}</dd>
    </div>
  );
}

export function ClientHeader({ client, siteName, actions }: { client: Client; siteName?: string; actions?: ReactNode }) {
  const expiring = agentCertExpiring(client);
  return (
    <section aria-label="Client summary" className="grid gap-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="grid min-w-0 gap-1">
          <h1 className="truncate text-xl font-semibold">{client.name}</h1>
          <div className="flex items-center gap-1.5">
            <ConnectionDot client={client} label={headerConnectionLabel(client)} />
            <HelpTip id="client.connection" />
          </div>
        </div>
        {actions && <div className="flex flex-wrap items-center gap-2">{actions}</div>}
      </div>
      <dl className="grid grid-cols-1 gap-x-6 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-4">
        <Fact label="Hostname">
          <span className="font-mono text-xs">{client.hostname || '–'}</span>
        </Fact>
        <Fact label="Site" help="client.site">
          {siteName ?? '–'}
        </Fact>
        <Fact label="Agent" help="client.agentVersion">
          {client.agentVersion ? <span className="font-mono text-xs">{`${client.agentVersion} · ${client.os}/${client.arch}`}</span> : '–'}
        </Fact>
        <Fact label="Agent certificate" help="client.agentCert">
          {!client.agentCertNotAfter ? (
            '–'
          ) : expiring ? (
            <ToneChip tone="expiring" icon={Clock} label={`Expires ${relDays(client.agentCertNotAfter)}`} />
          ) : (
            `Expires ${relDays(client.agentCertNotAfter)}`
          )}
        </Fact>
      </dl>
      {client.capabilities.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <ul aria-label="Capabilities" className="flex flex-wrap gap-1.5">
            {client.capabilities.map((c) => (
              <li key={c} className="inline-flex h-6 items-center rounded-sm border border-border bg-subtle px-2 font-mono text-xs">
                {c}
              </li>
            ))}
          </ul>
          <HelpTip id="client.capabilities" />
        </div>
      )}
      {client.status === 'pending' && client.tokenExpiresAt && (
        <p className="text-sm text-ink-muted">Token expires {fmtDateTime(client.tokenExpiresAt)}</p>
      )}
    </section>
  );
}
