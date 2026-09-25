import type { AuditEvent } from '@/api/types';
import { Sheet, SheetContent, SheetHeader, SheetTitle } from '@/components/ui/sheet';
import { fmtDateTime } from '@/lib/time';
import { DetailsDiff } from './DetailsDiff';

export function EventSheet({
  event,
  orgName,
  onClose,
  notice,
}: {
  event: AuditEvent | undefined;
  orgName: (id: string | null) => string;
  onClose: () => void;
  /** A one-line inline notice shown instead of the event (a deep link's ?event didn't resolve). */
  notice?: string;
}) {
  return (
    <Sheet open={event !== undefined || !!notice} onOpenChange={(o) => !o && onClose()}>
      <SheetContent className="grid content-start gap-4 overflow-y-auto sm:max-w-xl">
        <SheetHeader>
          <SheetTitle className="font-mono">{event?.action ?? 'Event not found'}</SheetTitle>
        </SheetHeader>
        {notice && <p className="text-sm text-ink-muted">{notice}</p>}
        {event && (
          <>
            <dl className="grid grid-cols-[96px_minmax(0,1fr)] gap-x-4 gap-y-1 text-sm">
              <dt className="text-ink-muted">Event</dt>
              <dd className="font-mono">#{event.id}</dd>
              <dt className="text-ink-muted">Time</dt>
              <dd>{fmtDateTime(event.ts)}</dd>
              <dt className="text-ink-muted">Actor</dt>
              <dd className="truncate">
                {event.actorName || '–'} <span className="font-mono text-xs text-ink-muted">{event.actorType} {event.actorId}</span>
              </dd>
              <dt className="text-ink-muted">Resource</dt>
              <dd className="truncate">
                {event.resourceType} <span className="font-mono text-xs">{event.resourceId}</span>
              </dd>
              <dt className="text-ink-muted">Org</dt>
              <dd>{orgName(event.orgId)}</dd>
              <dt className="text-ink-muted">IP</dt>
              <dd className="font-mono">{event.ip || '–'}</dd>
            </dl>
            <DetailsDiff details={event.details} />
          </>
        )}
      </SheetContent>
    </Sheet>
  );
}
