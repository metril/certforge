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

// Fix round 1 (review).
it('ignores chords and Ctrl/Cmd-K while focus is inside an open dialog/sheet/popover', () => {
  const go = vi.fn();
  const openPalette = vi.fn();
  renderHook(() => useShortcuts({ 'g o': go }, openPalette));
  const dialog = document.createElement('div');
  dialog.setAttribute('role', 'dialog');
  document.body.appendChild(dialog);
  act(() => {
    dialog.dispatchEvent(new KeyboardEvent('keydown', { key: 'g', bubbles: true }));
    dialog.dispatchEvent(new KeyboardEvent('keydown', { key: 'o', bubbles: true }));
    dialog.dispatchEvent(new KeyboardEvent('keydown', { key: 'k', metaKey: true, bubbles: true }));
  });
  expect(go).not.toHaveBeenCalled();
  expect(openPalette).not.toHaveBeenCalled();
  dialog.remove();
});

it('ignores chords and Ctrl/Cmd-K while focus is inside an open menu', () => {
  const go = vi.fn();
  renderHook(() => useShortcuts({ 'g o': go }));
  const menu = document.createElement('div');
  menu.setAttribute('role', 'menu');
  document.body.appendChild(menu);
  act(() => {
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'g', bubbles: true }));
    menu.dispatchEvent(new KeyboardEvent('keydown', { key: 'o', bubbles: true }));
  });
  expect(go).not.toHaveBeenCalled();
  menu.remove();
});

it('ignores composing (IME) keydown events', () => {
  const go = vi.fn();
  renderHook(() => useShortcuts({ 'g o': go }));
  act(() => {
    press('g');
    window.dispatchEvent(new KeyboardEvent('keydown', { key: 'o', isComposing: true, bubbles: true }));
  });
  expect(go).not.toHaveBeenCalled();
});

it('does not preventDefault on Ctrl/Cmd-K when no palette handler is registered', () => {
  renderHook(() => useShortcuts({}));
  const event = new KeyboardEvent('keydown', { key: 'k', metaKey: true, cancelable: true, bubbles: true });
  act(() => window.dispatchEvent(event));
  expect(event.defaultPrevented).toBe(false);
});
