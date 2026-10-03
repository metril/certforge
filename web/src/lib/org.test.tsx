import { renderHook } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useOrgSlugOf } from './org';

const me = { orgs: [{ id: 'o-1', slug: 'acme' }] };

vi.mock('@tanstack/react-router', async (orig) => ({
  ...(await orig<typeof import('@tanstack/react-router')>()),
  useRouteContext: () => me,
}));

it('useOrgSlugOf returns the same callback across renders', () => {
  const { result, rerender } = renderHook(() => useOrgSlugOf());
  const first = result.current;
  rerender();
  expect(result.current).toBe(first);
  expect(first('o-1')).toBe('acme');
});
