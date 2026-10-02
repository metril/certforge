import { Globe } from 'lucide-react';
import { Link } from '@tanstack/react-router';
import type { NotifyEvent } from '@/api/types';
import { ToneChip } from '@/components/StatusChip';
import { KIND_LABEL, SEVERITY_META } from '@/lib/events';
import { fmtDateTime, relTime } from '@/lib/time';
import { DeliverySummary } from './DeliveryChip';

const linkCls = 'shrink-0 truncate font-medium hover:underline';

/** Task 5 layout: certificate/client/monitor/channel/backup resources link
 * to their own page or sheet; a grant (deploy.* events) shows its name only
 * (Shared contracts: a grant's name is already "<cert> -> <client or
 * target>", so no further page to link to). */
export function ResourceLink({ event, org, className = linkCls }: { event: NotifyEvent; org: string; className?: string }) {
  const { resource } = event;
  switch (resource.type) {
    case 'certificate':
      return (
        <Link to="/o/$org/certificates/$id/$tab" params={{ org, id: resource.id, tab: 'overview' }} className={className}>
          {resource.name}
        </Link>
      );
    case 'client':
      return (
        <Link to="/o/$org/clients/$id" params={{ org, id: resource.id }} className={className}>
          {resource.name}
        </Link>
      );
    case 'monitor':
      return (
        <Link to="/o/$org/alerts/monitors" params={{ org }} search={{ edit: resource.id }} className={className}>
          {resource.name}
        </Link>
      );
    case 'channel':
      return (
        <Link to="/o/$org/alerts/channels" params={{ org }} search={{ edit: resource.id }} className={className}>
          {resource.name}
        </Link>
      );
    case 'backup':
      return (
        <Link to="/settings/$section" params={{ section: 'backup' }} className={className}>
          {resource.name}
        </Link>
      );
    default:
      return <span className={className.replace('hover:underline', '')}>{resource.name}</span>;
  }
}

export function EventRow({ event, org }: { event: NotifyEvent; org: string }) {
  const sev = SEVERITY_META[event.severity];
  return (
    <div className="grid gap-1.5 border-b border-border py-3 last:border-0">
      <div className="flex flex-wrap items-center gap-2">
        <ToneChip tone={sev.tone} icon={sev.icon} label={sev.label} />
        <span className="font-semibold">{KIND_LABEL[event.kind]}</span>
        <span title={fmtDateTime(event.at)} className="text-xs text-ink-muted">
          {relTime(event.at)}
        </span>
        {event.orgId === null && <ToneChip tone="neutral" icon={Globe} label="Global" />}
      </div>
      <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <p className="min-w-0 flex-1 text-sm md:line-clamp-2">{event.summary}</p>
        <ResourceLink event={event} org={org} />
      </div>
      <div className="flex items-center">
        <DeliverySummary deliveries={event.deliveries} />
      </div>
    </div>
  );
}
