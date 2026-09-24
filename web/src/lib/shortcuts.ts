import { useEffect, useRef } from 'react';

export type ChordMap = Record<string, () => void>;

const CHORD_WINDOW_MS = 900;

// Fix round 1 (review): shortcuts were firing while a dialog, sheet,
// popover (Radix renders all three with role="dialog"), dropdown/context
// menu (role="menu"), or listbox (e.g. a future cmdk combobox) had focus —
// typing to filter a list or naming a field could trigger "g o" navigation
// out from under the open surface.
const SUPPRESS_SELECTOR = '[role="dialog"],[role="alertdialog"],[role="menu"],[role="listbox"]';

function isSuppressed(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)) return true;
  return target.closest(SUPPRESS_SELECTOR) !== null;
}

/**
 * Global "g x" chord shortcuts (spec, Cross-cutting patterns: `g o`, `g c`,
 * `g l`) and the Ctrl/Cmd-K binding. The command palette itself is Task 17;
 * this hook is the registry it plugs handlers into and the binding it
 * reuses for Ctrl/Cmd-K, so both exist ahead of the palette UI. Ignored
 * while focus is in a text input, an IME composition is in progress, or
 * focus is inside a dialog/sheet/popover/menu/listbox, so typing "g" (or
 * opening the palette) doesn't misfire.
 */
export function useShortcuts(chords: ChordMap, onOpenPalette?: () => void): void {
  const pendingG = useRef(false);
  const timer = useRef<ReturnType<typeof setTimeout>>();
  const chordsRef = useRef(chords);
  chordsRef.current = chords;
  const paletteRef = useRef(onOpenPalette);
  paletteRef.current = onOpenPalette;

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.isComposing || isSuppressed(e.target)) return;
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        // Only claim the browser's own Ctrl/Cmd-K (address-bar search in
        // some browsers) once a handler is actually registered — Task 17
        // wires `onOpenPalette` in; until then, don't swallow it for nothing.
        if (paletteRef.current) {
          e.preventDefault();
          paletteRef.current();
        }
        return;
      }
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const key = e.key.toLowerCase();
      if (pendingG.current) {
        pendingG.current = false;
        clearTimeout(timer.current);
        const handler = chordsRef.current[`g ${key}`];
        if (handler) {
          e.preventDefault();
          handler();
        }
        return;
      }
      if (key === 'g') {
        pendingG.current = true;
        timer.current = setTimeout(() => (pendingG.current = false), CHORD_WINDOW_MS);
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      clearTimeout(timer.current);
    };
  }, []);
}
