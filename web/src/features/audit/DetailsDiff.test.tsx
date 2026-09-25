import { expect, it } from 'vitest';
import { diffDetails } from './DetailsDiff';

it('lists changed, added and removed fields and keeps the rest', () => {
  const d = diffDetails({ section: 'general', before: { a: 1, b: 'x', c: { n: 1 } }, after: { a: 1, b: 'y', d: true, c: { n: 1 } } });
  expect(d?.rows).toEqual([
    { key: 'b', before: '"x"', after: '"y"', kind: 'changed' },
    { key: 'd', before: undefined, after: 'true', kind: 'added' },
  ]);
  expect(d?.rest).toEqual({ section: 'general' });
  expect(diffDetails({ before: { gone: 1 }, after: {} })?.rows).toEqual([{ key: 'gone', before: '1', after: undefined, kind: 'removed' }]);
});

it('returns null without before and after', () => {
  expect(diffDetails({ name: 'x' })).toBeNull();
  expect(diffDetails({ before: 'not an object' })).toBeNull();
});
