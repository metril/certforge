export const POLL = { live: 2_000, list: 30_000 } as const;

/** 2 s while something is in flight, 30 s otherwise. Hidden tabs never poll (refetchIntervalInBackground stays false). */
export function livePoll(active: boolean): number {
  return active ? POLL.live : POLL.list;
}

/** For infinite queries: refetching re-requests every loaded page, so poll only while the first page alone is loaded. */
export function firstPagePoll(q: { state: { data?: { pages: unknown[] } } }): number | false {
  return q.state.data?.pages.length === 1 ? POLL.list : false;
}
