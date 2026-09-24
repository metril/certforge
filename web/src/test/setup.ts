import '@testing-library/jest-dom/vitest';
import { afterAll, afterEach, beforeAll, beforeEach, vi } from 'vitest';
import { cleanup } from '@testing-library/react';
import { server } from './server';
import { NOW } from './fixtures';

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
// tests, reset between them below.
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
