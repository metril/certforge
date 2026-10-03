import { describe, expect, it } from 'vitest';
import { firstPagePoll, livePoll, POLL } from './polling';

const q = (pages?: unknown[]) => ({ state: { data: pages && { pages } } });

describe('firstPagePoll', () => {
  it('polls only while exactly one page is loaded', () => {
    expect(firstPagePoll(q([{}]))).toBe(POLL.list);
    expect(firstPagePoll(q([{}, {}]))).toBe(false);
    expect(firstPagePoll(q([]))).toBe(false);
    expect(firstPagePoll(q())).toBe(false);
  });
});

describe('livePoll', () => {
  it('is faster while active', () => {
    expect(livePoll(true)).toBe(POLL.live);
    expect(livePoll(false)).toBe(POLL.list);
  });
});
