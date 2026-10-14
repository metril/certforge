import { http, HttpResponse } from 'msw';
import { screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, grantServer, url } from '@/test/fixtures';
import { renderUI } from '@/test/render';
import { GrantCheckHook } from './GrantCheckHook';

const TOKEN = 'cf_abcdef012345_secret';
const hookUrl = 'https://cf.example.test/hooks/v1/grants/g-1/check';

it('is disabled without a verify endpoint', () => {
  server.use(...authHandlers({ authed: true }));
  renderUI(<GrantCheckHook orgId="org-1" grant={{ ...grantServer, monitorId: null }} canWrite />);
  expect(screen.getByRole('button', { name: /check hook for/i })).toHaveAttribute('aria-disabled', 'true');
});

it('generates a token, shows it once, and revokes', async () => {
  let deleted = 0;
  server.use(
    ...authHandlers({ authed: true }),
    http.post(url('/orgs/org-1/grants/:id/check-token'), () => HttpResponse.json({ token: TOKEN, url: hookUrl }, { status: 201 })),
    http.delete(url('/orgs/org-1/grants/:id/check-token'), () => {
      deleted++;
      return new HttpResponse(null, { status: 204 });
    }),
  );
  const user = userEvent.setup();
  const grant = { ...grantServer, monitorId: 'm-1', checkTokenSet: true };
  renderUI(<GrantCheckHook orgId="org-1" grant={grant} canWrite />);
  await user.click(screen.getByRole('button', { name: /check hook for/i }));
  expect(screen.queryByText(TOKEN)).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Rotate' }));
  expect(await screen.findByText(TOKEN)).toBeInTheDocument();
  expect(screen.getByText(hookUrl)).toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: 'Revoke' }));
  await waitFor(() => expect(deleted).toBe(1));
  await waitFor(() => expect(screen.queryByText(TOKEN)).not.toBeInTheDocument());
});
