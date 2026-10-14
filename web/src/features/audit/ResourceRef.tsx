import type { ReactNode } from 'react';
import type { AuditEvent } from '@/api/types';
import { EntityLink, RESOURCE_KIND } from '@/components/EntityLink';

// A row (or card) around these opens the event, so a click on the link must stay on the link.
function Inert({ children }: { children: ReactNode }) {
  return <span className="min-w-0" onClick={(e) => e.stopPropagation()}>{children}</span>;
}

/** The record's resource id, linked to its page when its type has one; the plain id once the object is gone or has no page. */
export function ResourceId({ event, className }: { event: Pick<AuditEvent, 'resourceType' | 'resourceId' | 'orgId'>; className?: string }) {
  const kind = RESOURCE_KIND[event.resourceType];
  const id = <span className={className}>{event.resourceId}</span>;
  if (!kind) return id;
  return (
    <Inert>
      <EntityLink kind={kind} id={event.resourceId} orgId={event.orgId}>
        {id}
      </EntityLink>
    </Inert>
  );
}

/** The actor's name, linked to the user (or API key) it names. */
export function ActorName({ event, children }: { event: Pick<AuditEvent, 'actorType' | 'actorId'>; children: ReactNode }) {
  const kind = event.actorType === 'user' ? 'user' : event.actorType === 'apikey' ? 'apiKey' : undefined;
  if (!kind) return <>{children}</>;
  return (
    <Inert>
      <EntityLink kind={kind} id={event.actorId}>
        {children}
      </EntityLink>
    </Inert>
  );
}
