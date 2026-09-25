import { useEffect, useRef } from 'react';

export type ChordMap = Record<string, () => void>;

const CHORD_WINDOW_MS = 900;

// Fix round 1 (review): shortcuts were firing while a dialog, sheet,
// popover (Radix renders all three with role="dialog"), dropdown/context
// menu (role="menu"), or listbox (e.g. a future cmdk combobox) had focus —
// typing to filter a list or naming a field could trigger "g o" navigation
// out from under the open surface.
const SUPPRESS_SELECTOR = '[role="dialog"],[role="alertdialog"],[role="menu"],[role="listbox"]';
// CommandPalette.tsx's own dialog (its `className="cf-command-palette"` on
// CommandDialog's DialogContent) — the one exception to SUPPRESS_SELECTOR,
// and only for Ctrl/Cmd-K (see isPalette's use below).
const PALETTE_SELECTOR = '.cf-command-palette';

function isSuppressed(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  if (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)) return true;
  return target.closest(SUPPRESS_SELECTOR) !== null;
}

function isPalette(target: EventTarget | null): boolean {
  return target instanceof HTMLElement && target.closest(PALETTE_SELECTOR) !== null;
}

/**
 * Global two-key chord shortcuts (spec, Cross-cutting patterns: `g o`,
 * `g c`, `g l`, and Task 17's `n c`) and the Ctrl/Cmd-K binding. The command
 * palette itself is Task 17; this hook is the registry it plugs handlers
 * into and the binding it reuses for Ctrl/Cmd-K. Any first key present in
 * `chords` (not just "g") can start a sequence — a second key within
 * `CHORD_WINDOW_MS` that doesn't complete a known chord is dropped, and the
 * key that broke the sequence is then itself tried as a fresh first key
 * (matching the brief's shortcuts test: "g", "x", "n", "c" runs `n c` once,
 * not "g x" as a no-op that also eats "n"). Ignored while focus is in a
 * text input, an IME composition is in progress, or focus is inside a
 * dialog/sheet/popover/menu/listbox, so typing "g" (or "n") doesn't misfire.
 *
 * Ctrl/Cmd-K is exempt from suppression only when focus is inside the
 * palette's own dialog (`isPalette`, matched via CommandPalette's
 * `cf-command-palette` class): its `CommandInput` is an `<input>` inside a
 * `[role="dialog"]`, both of which the suppress selector matches, so
 * without this exemption a second Ctrl/Cmd-K while the palette has focus
 * would never reach `onOpenPalette`, and the palette could only be opened,
 * never closed the same way. Every other dialog/sheet/popover/menu/listbox
 * still suppresses Ctrl/Cmd-K, same as any other shortcut (Task 4 fix
 * round 1's own test for this).
 */
export function useShortcuts(chords: ChordMap, onOpenPalette?: () => void): void {
  const pendingKey = useRef<string | null>(null);
  const timer = useRef<ReturnType<typeof setTimeout>>();
  const chordsRef = useRef(chords);
  chordsRef.current = chords;
  const paletteRef = useRef(onOpenPalette);
  paletteRef.current = onOpenPalette;

  useEffect(() => {
    function onKeyDown(e: KeyboardEvent) {
      if (e.isComposing) return;
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        if (isSuppressed(e.target) && !isPalette(e.target)) return;
        // Only claim the browser's own Ctrl/Cmd-K (address-bar search in
        // some browsers) once a handler is actually registered — Task 17
        // wires `onOpenPalette` in; until then, don't swallow it for nothing.
        if (paletteRef.current) {
          e.preventDefault();
          paletteRef.current();
        }
        return;
      }
      if (isSuppressed(e.target)) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const key = e.key.toLowerCase();
      if (pendingKey.current) {
        const combo = `${pendingKey.current} ${key}`;
        pendingKey.current = null;
        clearTimeout(timer.current);
        const handler = chordsRef.current[combo];
        if (handler) {
          e.preventDefault();
          handler();
          return;
        }
        // No such chord: fall through so this key can itself start a new
        // sequence instead of being silently dropped.
      }
      if (Object.keys(chordsRef.current).some((k) => k.startsWith(`${key} `))) {
        pendingKey.current = key;
        timer.current = setTimeout(() => (pendingKey.current = null), CHORD_WINDOW_MS);
      }
    }
    window.addEventListener('keydown', onKeyDown);
    return () => {
      window.removeEventListener('keydown', onKeyDown);
      clearTimeout(timer.current);
    };
  }, []);
}
