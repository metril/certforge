import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { makeAttempt } from '@/test/fixtures';
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
