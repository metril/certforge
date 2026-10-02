import { infiniteQueryOptions } from '@tanstack/react-query';
import { api, call } from '../client';
import type { EventKind, EventPage, Severity } from '../types';

export type EventsFilter = { kind?: EventKind[]; severity?: Severity; /** RFC 3339 lower bound; keep it stable between renders (the query key). */ since?: string };

export const eventsQuery = (orgId: string, f: EventsFilter) =>
  infiniteQueryOptions({
    queryKey: ['events', orgId, f],
    queryFn: ({ pageParam }) =>
      call(
        api.GET('/orgs/{orgId}/events', {
          params: { path: { orgId }, query: { kind: f.kind, severity: f.severity, since: f.since, cursor: pageParam } },
        }),
      ),
    initialPageParam: undefined as string | undefined,
    getNextPageParam: (last) => last.nextCursor ?? undefined,
    // Only while a delivery already on a loaded page is still pending
    // (Review Focus "polling that never stops" — T5 "polls only while pending").
    refetchInterval: (q) => {
      const pages = (q.state.data?.pages ?? []) as EventPage[];
      const pending = pages.some((p) => p.items.some((e) => e.deliveries.some((d) => d.status === 'pending')));
      return pending ? 5000 : false;
    },
  });
