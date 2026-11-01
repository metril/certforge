import { act } from '@testing-library/react';
import { vi } from 'vitest';

// msw 3 no longer replaces fetch: the real (jsdom/undici) fetch runs and msw
// answers on an intercepted socket, so a mocked response lands on a real
// macrotask, never within the fake clock. vi.advanceTimersByTimeAsync only
// drains microtasks between fake timers, so a request a timer fires partway
// through one long jump would not resolve until after the jump, and every
// poll scheduled off that response would slip. setImmediate is never in any
// test's toFake list, so it is always the real event loop.
const STEP_MS = 50;
const REAL_TURNS = 3;

/** Let any in-flight mocked responses land (real event-loop turns). */
export async function settleNetwork() {
  for (let i = 0; i < REAL_TURNS; i++) await new Promise<void>((resolve) => setImmediate(resolve));
}

/**
 * Advance the fake clock by `ms` in small steps, letting in-flight mocked
 * responses land after each step, all inside act().
 */
export function advance(ms: number) {
  return act(async () => {
    await settleNetwork();
    for (let left = ms; left > 0; left -= STEP_MS) {
      await vi.advanceTimersByTimeAsync(Math.min(STEP_MS, left));
      await settleNetwork();
    }
  });
}
