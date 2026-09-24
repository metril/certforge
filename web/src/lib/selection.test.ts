import { expect, it } from 'vitest';
import { nextSelection } from './selection';

const ids = ['a', 'b', 'c', 'd', 'e'];

it('toggles a single row and sets the anchor', () => {
  const r = nextSelection(new Set(), ids, 'b', { shift: false, anchor: null });
  expect([...r.selected]).toEqual(['b']);
  expect(r.anchor).toBe('b');
  expect([...nextSelection(r.selected, ids, 'b', { shift: false, anchor: 'b' }).selected]).toEqual([]);
});

it('adds a range on shift-click in either direction', () => {
  expect([...nextSelection(new Set(['b']), ids, 'd', { shift: true, anchor: 'b' }).selected].sort()).toEqual(['b', 'c', 'd']);
  expect([...nextSelection(new Set(['d']), ids, 'a', { shift: true, anchor: 'd' }).selected].sort()).toEqual(['a', 'b', 'c', 'd']);
});

it('treats shift-click without a live anchor as a plain toggle', () => {
  expect([...nextSelection(new Set(), ids, 'c', { shift: true, anchor: 'zz' }).selected]).toEqual(['c']);
});
