import type { ReactElement } from 'react';
import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { Providers } from '@/app/Providers';
import { iso, makeAttempt } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { AttemptLogViewer } from './AttemptLogViewer';

it('opens with the failing step expanded, one-line explanation, and a collapsed raw log', async () => {
  const { user } = renderUI(<AttemptLogViewer attempt={makeAttempt()} defaultOpen />);
  expect(screen.getByText('Failed')).toBeInTheDocument();
  expect(screen.getByText('A DNS lookup failed during validation.')).toBeInTheDocument();
  expect(screen.getByText('NXDOMAIN looking up TXT for _acme-challenge.www.example.com')).toBeInTheDocument();
  expect(screen.queryByText('requesting order')).toBeNull();
  await user.click(screen.getByRole('button', { name: 'Raw log' }));
  expect(screen.getByText('requesting order')).toBeInTheDocument();
  await user.type(screen.getByLabelText('Search log'), 'nxdomain');
  expect(screen.queryByText('requesting order')).toBeNull();
  expect(screen.getByText('error: NXDOMAIN looking up TXT')).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Copy log' }));
  expect(await navigator.clipboard.readText()).toContain('presenting dns-01');
});

// Fix round 1 (review, Important #1): StepRow used to read `expanded` into
// state only at mount, so a step that turns from running to failed on a
// later render (same key, same instance) kept its message hidden with no
// way to open it (the toggle only renders while `!expanded`).
it("shows a step's message once it turns from running to failed on a later render", () => {
  const running = makeAttempt({
    outcome: 'running',
    finishedAt: undefined,
    acmeErrorType: undefined,
    retryAfter: undefined,
    steps: [
      { name: 'account', status: 'success', startedAt: iso(-0.01), finishedAt: iso(-0.0099) },
      { name: 'challenge www.example.com', status: 'running', startedAt: iso(-0.0098) },
    ],
  });
  const { rerender, queryClient } = renderUI(<AttemptLogViewer attempt={running} defaultOpen />);
  const wrap = (ui: ReactElement) => <Providers queryClient={queryClient}>{ui}</Providers>;
  expect(screen.queryByText(/NXDOMAIN/)).toBeNull();

  const failed = makeAttempt({
    steps: [
      { name: 'account', status: 'success', startedAt: iso(-0.01), finishedAt: iso(-0.0099) },
      {
        name: 'challenge www.example.com',
        status: 'failed',
        startedAt: iso(-0.0098),
        finishedAt: iso(-0.009),
        message: 'NXDOMAIN looking up TXT for _acme-challenge.www.example.com',
      },
    ],
  });
  rerender(wrap(<AttemptLogViewer attempt={failed} defaultOpen />));
  expect(screen.getByText('NXDOMAIN looking up TXT for _acme-challenge.www.example.com')).toBeInTheDocument();
});

it('guards Copy log when the Clipboard API is unavailable', async () => {
  const original = navigator.clipboard;
  try {
    const { user } = renderUI(<AttemptLogViewer attempt={makeAttempt()} defaultOpen />);
    await user.click(screen.getByRole('button', { name: 'Raw log' }));
    // renderUI's userEvent.setup() installs its own navigator.clipboard stub,
    // so the override has to happen after render, not before (same pattern
    // as controls.test.tsx's CopyField clipboard tests).
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: undefined });
    await user.click(screen.getByRole('button', { name: 'Copy log' }));
    expect(await screen.findByText('Copy failed')).toBeInTheDocument();
  } finally {
    Object.defineProperty(navigator, 'clipboard', { configurable: true, value: original });
  }
});
