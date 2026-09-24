export const POLL = { live: 2_000, list: 30_000 } as const;

/** 2 s while something is in flight, 30 s otherwise. Hidden tabs never poll (refetchIntervalInBackground stays false). */
export function livePoll(active: boolean): number {
  return active ? POLL.live : POLL.list;
}
