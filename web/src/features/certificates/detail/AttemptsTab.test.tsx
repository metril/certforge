import { http, HttpResponse } from 'msw';
import { act, screen } from '@testing-library/react';
import { focusManager } from '@tanstack/react-query';
import { afterEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { makeAttempt, NOW, url } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { AttemptsTab } from './AttemptsTab';

afterEach(() => focusManager.setFocused(undefined));

const tick = (ms: number) => act(async () => { await vi.advanceTimersByTimeAsync(ms); });

it('polls a running attempt every 2 s, stops while hidden, and refetches once on return', async () => {
  vi.useFakeTimers({ now: NOW, toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
  let calls = 0;
  server.use(
    http.get(url('/orgs/org-1/certificates/c-1/attempts'), () => {
      calls++;
      return HttpResponse.json([makeAttempt({ outcome: 'running', finishedAt: undefined, acmeErrorType: undefined, retryAfter: undefined })]);
    }),
  );
  renderUI(<AttemptsTab orgId="org-1" certId="c-1" />);
  await tick(50);
  expect(screen.getByText('Running')).toBeInTheDocument();
  const first = calls;

  await tick(2_050);
  expect(calls).toBe(first + 1);

  act(() => focusManager.setFocused(false));
  await tick(10_000);
  expect(calls).toBe(first + 1);

  act(() => focusManager.setFocused(true));
  await tick(50);
  expect(calls).toBe(first + 2);

  await tick(2_100);
  expect(calls).toBeGreaterThanOrEqual(first + 3);
});

it('slows to 30 s once no attempt is running', async () => {
  vi.useFakeTimers({ now: NOW, toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] });
  let calls = 0;
  server.use(http.get(url('/orgs/org-1/certificates/c-1/attempts'), () => (calls++, HttpResponse.json([makeAttempt()]))));
  renderUI(<AttemptsTab orgId="org-1" certId="c-1" />);
  await tick(50);
  const first = calls;
  await tick(10_000);
  expect(calls).toBe(first);
  await tick(20_100);
  expect(calls).toBe(first + 1);
});
