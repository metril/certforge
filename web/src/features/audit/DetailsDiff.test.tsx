import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { renderUI } from '@/test/render';
import { diffDetails, DetailsDiff } from './DetailsDiff';

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

// M2: Copy JSON used to fire navigator.clipboard.writeText unguarded — an
// unavailable Clipboard API (a LAN deployment over plain http) must surface
// as a visible failure instead of an unhandled rejection, mirroring
// CopyField's own guarded copy (components/controls.test.tsx).
it('shows a failure icon when the Clipboard API is unavailable', async () => {
  const original = navigator.clipboard;
  try {
    const { user } = renderUI(<DetailsDiff details={{ name: 'x' }} />);
    await user.click(screen.getByRole('button', { name: 'Raw details' }));
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined });
    await user.click(screen.getByRole('button', { name: 'Copy JSON' }));
    expect(await screen.findByText('Copy failed')).toBeInTheDocument();
  } finally {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: original });
  }
});

it('copies the JSON to the clipboard when available', async () => {
  const { user } = renderUI(<DetailsDiff details={{ name: 'x' }} />);
  await user.click(screen.getByRole('button', { name: 'Raw details' }));
  await user.click(screen.getByRole('button', { name: 'Copy JSON' }));
  expect(await navigator.clipboard.readText()).toBe(JSON.stringify({ name: 'x' }, null, 2));
});
