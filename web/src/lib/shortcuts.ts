import { useEffect, useRef } from 'react';

export type ChordMap = Record<string, () => void>;

const CHORD_WINDOW_MS = 900;

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  return target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName);
}

/**
 * Global "g x" chord shortcuts (spec, Cross-cutting patterns: `g o`, `g c`,
 * `g l`) and the Ctrl/Cmd-K binding. The command palette itself is Task 17;
 * this hook is the registry it plugs handlers into and the binding it
 * reuses for Ctrl/Cmd-K, so both exist ahead of the palette UI. Ignored
 * while focus is in a text input so typing "g" doesn't misfire.
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
      if (isTypingTarget(e.target)) return;
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        paletteRef.current?.();
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
