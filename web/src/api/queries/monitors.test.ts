import { expect, it } from 'vitest';
import { POLL } from '@/lib/polling';
import { monitorsQuery } from './monitors';

it('monitorsQuery polls at the list pace', () => {
  expect(monitorsQuery('org-1').refetchInterval).toBe(POLL.list);
});
