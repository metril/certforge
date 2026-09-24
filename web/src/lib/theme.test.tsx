import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { act, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { TooltipProvider } from '@/components/ui/tooltip';
import { ThemeToggle } from '@/components/ThemeToggle';
import { THEME_KEY, ThemeProvider } from './theme';

const root = resolve(import.meta.dirname, '../..');
const initScript = readFileSync(resolve(root, 'public/theme-init.js'), 'utf8');

function mockSystem(dark: boolean) {
  vi.stubGlobal('matchMedia', (q: string) => ({
    matches: dark && q.includes('dark'),
    media: q,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}
function runInit(stored: string | null, systemDark: boolean) {
  document.documentElement.removeAttribute('data-theme');
  if (stored) localStorage.setItem(THEME_KEY, stored);
  mockSystem(systemDark);
  new Function(initScript)();
  return document.documentElement.getAttribute('data-theme');
}

// Adaptation (preflight D1 / controller ruling): also restore mocks, not just
// stubbed globals — vi.spyOn(Storage.prototype, ...) below leaks into later
// test files' localStorage.getItem otherwise.
afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe('theme-init.js (pre-paint)', () => {
  it.each([
    ['dark', false, 'dark'],
    ['light', true, 'light'],
    [null, true, 'dark'],
    [null, false, 'light'],
  ])('stored=%s systemDark=%s → %s', (stored, sys, expected) => {
    expect(runInit(stored, sys)).toBe(expected);
  });

  it('falls back to light when storage throws', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => {
      throw new Error('blocked');
    });
    expect(runInit(null, true)).toBe('light');
  });

  it('runs synchronously in <head> before styles and the module script', () => {
    const html = readFileSync(resolve(root, 'index.html'), 'utf8');
    const head = html.slice(0, html.indexOf('</head>'));
    // Classic, no async/defer: it blocks parsing, so it runs before the stylesheet and module Vite append to <head>.
    expect(head).toContain('<script src="/theme-init.js"></script>');
    expect(head).not.toMatch(/type="module"|rel="stylesheet"/);
  });
});

describe('ThemeProvider + ThemeToggle', () => {
  it('persists an explicit choice and clears it for System', async () => {
    mockSystem(false);
    const user = userEvent.setup();
    render(
      <ThemeProvider>
        <TooltipProvider>
          <ThemeToggle />
        </TooltipProvider>
      </ThemeProvider>,
    );
    await user.click(screen.getByRole('radio', { name: 'Dark' }));
    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(localStorage.getItem(THEME_KEY)).toBe('dark');
    await act(() => user.click(screen.getByRole('radio', { name: 'System' })));
    expect(localStorage.getItem(THEME_KEY)).toBeNull();
    expect(document.documentElement.dataset.theme).toBe('light');
  });
});
