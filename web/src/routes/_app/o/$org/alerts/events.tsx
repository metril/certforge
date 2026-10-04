import { createFileRoute } from '@tanstack/react-router';
import { z } from 'zod';
import type { EventKind } from '@/api/types';
import { KIND_LABEL } from '@/lib/events';
import { EventsPage } from '@/features/alerts/EventsPage';

// KIND_LABEL is a Record<EventKind, string>, so the compiler keeps this list in step with the API's EventKind.
const KNOWN_KINDS: ReadonlySet<string> = new Set(Object.keys(KIND_LABEL));
// An unknown entry is dropped instead of discarding the whole array.
const eventKinds = z.array(z.string()).transform((a) => a.filter((k): k is EventKind => KNOWN_KINDS.has(k)));
const severity = z.enum(['warning', 'critical']);

export const Route = createFileRoute('/_app/o/$org/alerts/events')({
  validateSearch: z.object({
    // Group/kind filter (repeatable) and the severity floor (task 5).
    kind: eventKinds.optional().catch(undefined),
    severity: severity.optional().catch(undefined),
    // Time window; absent means all time.
    range: z.enum(['24h', '7d', '30d']).optional().catch(undefined),
  }),
  component: EventsPage,
});
