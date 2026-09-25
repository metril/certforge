import '@testing-library/jest-dom/vitest';
import { afterAll, afterEach, beforeAll, beforeEach, vi } from 'vitest';
import { cleanup, configure } from '@testing-library/react';
import { server } from './server';
import { NOW } from './fixtures';

// C1: a `console.error` almost always means a real bug (a React warning about
// refs, act(), keys, prop types, etc.) that a merely-passing assertion would
// miss; fail the test outright instead of letting it scroll by unnoticed.
// No allowlist: every current call site is fixed rather than silenced.
const rawConsoleError = console.error;
console.error = (...args: Parameters<typeof console.error>) => {
  rawConsoleError(...args);
  throw new Error(`console.error called in test: ${args.map(String).join(' ')}`);
};

// I4: RJSF/Ajv/tldts cold-load slowly the first time a lazy chunk imports
// them; give async utilities (waitFor, findBy*) more headroom than the 1000ms
// default so a slow first import doesn't flake a test that is otherwise
// correct.
configure({ asyncUtilTimeout: 3000 });

// jsdom gaps used by Radix, cmdk, and dnd-kit.
class NoopResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver ??= NoopResizeObserver as unknown as typeof ResizeObserver;
// Adaptation: some test files opt into `@vitest-environment node` (lint.test.ts,
// tokens.test.ts) where these DOM globals don't exist; setupFiles still run for
// them, so guard the jsdom-only patches instead of assuming jsdom is present.
if (typeof Element !== 'undefined') {
  Element.prototype.scrollIntoView ??= function scrollIntoView() {};
  Element.prototype.hasPointerCapture ??= () => false;
  Element.prototype.releasePointerCapture ??= () => {};
}
if (typeof window !== 'undefined') {
  // dnd-kit's KeyboardSensor calls scrollIntoViewIfNeeded on drag start,
  // which falls back to window.scrollTo; jsdom *does* define scrollTo (so
  // `??=` never applies), but its body just logs "Not implemented" to
  // stderr for every such test — replace it outright, not conditionally.
  window.scrollTo = (() => {}) as typeof window.scrollTo;
  window.matchMedia ??= (query: string) =>
    ({
      matches: false,
      media: query,
      onchange: null,
      addEventListener: () => {},
      removeEventListener: () => {},
      addListener: () => {},
      removeListener: () => {},
      dispatchEvent: () => false,
    }) as MediaQueryList;
}
// jsdom has no Clipboard API (Task 5 preflight: CopyField needs
// navigator.clipboard.writeText/readText); an in-memory stub is enough for
// tests, reset between them below. Note: @testing-library/user-event's
// userEvent.setup() (called by every renderUI) installs its OWN
// navigator.clipboard stub the first time a test renders, which overrides
// this one — a test that wants to control navigator.clipboard itself (e.g.
// to simulate a rejected write) must override it after calling renderUI,
// not before.
let clipboardText = '';
if (typeof navigator !== 'undefined' && !navigator.clipboard) {
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: {
      writeText: async (text: string) => {
        clipboardText = text;
      },
      readText: async () => clipboardText,
    },
  });
}

beforeAll(() => server.listen({ onUnhandledRequest: 'error' }));
// Every relative date ("in 60 d") in fixtures.ts is computed from this fixed
// clock; only Date is faked so setTimeout-driven query polling still runs.
beforeEach(() => {
  vi.useFakeTimers({ now: NOW, toFake: ['Date'], shouldAdvanceTime: true });
});
afterEach(() => {
  vi.useRealTimers();
  cleanup();
  server.resetHandlers();
  if (typeof localStorage !== 'undefined') localStorage.clear();
  clipboardText = '';
});
afterAll(() => server.close());
