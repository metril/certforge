import { act, renderHook } from '@testing-library/react';
import { expect, it, vi } from 'vitest';
import { useShortcuts } from './shortcuts';

function press(key: string, opts: Partial<KeyboardEventInit> = {}) {
  window.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, ...opts }));
}

it('fires a chord handler for "g" then the second key', () => {
  const go = vi.fn();
  renderHook(() => useShortcuts({ 'g o': go }));
  act(() => {
    press('g');
    press('o');
  });
  expect(go).toHaveBeenCalledTimes(1);
});

it('does not fire on the second key alone', () => {
  const go = vi.fn();
  renderHook(() => useShortcuts({ 'g o': go }));
  act(() => press('o'));
  expect(go).not.toHaveBeenCalled();
});

it('ignores chords while typing in a field', () => {
  const go = vi.fn();
  renderHook(() => useShortcuts({ 'g o': go }));
  const input = document.createElement('input');
  document.body.appendChild(input);
  act(() => {
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'g', bubbles: true }));
    input.dispatchEvent(new KeyboardEvent('keydown', { key: 'o', bubbles: true }));
  });
  expect(go).not.toHaveBeenCalled();
  input.remove();
});

it('reserves Ctrl/Cmd-K for the command palette binding', () => {
  const openPalette = vi.fn();
  renderHook(() => useShortcuts({}, openPalette));
  act(() => press('k', { metaKey: true }));
  expect(openPalette).toHaveBeenCalledTimes(1);
  act(() => press('k', { ctrlKey: true }));
  expect(openPalette).toHaveBeenCalledTimes(2);
});
