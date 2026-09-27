import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeAuditEvent, makeClient, makeHookRun, meWith, org, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let auditQuery: URLSearchParams;

beforeEach(() => {
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/clients/cl-1'), () => HttpResponse.json(makeClient())),
    http.get(url('/orgs/org-1/clients/cl-1/grants'), () => HttpResponse.json({ items: [] })),
    http.get(url('/orgs/org-1/clients/cl-1/hook-runs'), () =>
      HttpResponse.json({
        items: [
          makeHookRun({ id: 'hr-1', stdout: 'reloaded\n' }),
          makeHookRun({ id: 'hr-2', exitCode: 2, stderr: 'nginx: [emerg] bad config', durationMs: 1400 }),
          makeHookRun({ id: 'hr-3', hookId: null, hookName: '', exitCode: -1, phase: 'pre_deploy' }),
          makeHookRun({ id: 'hr-4', exitCode: -1, stderr: '[certforge-agent: killed after 30s]', durationMs: 30_000 }),
        ],
        nextCursor: null,
      }),
    ),
    http.get(url('/audit'), ({ request }) => {
      auditQuery = new URL(request.url).searchParams;
      return HttpResponse.json({
        items: [makeAuditEvent({ id: 7, action: 'deployment.drift', actorType: 'agent', actorId: 'cl-1', actorName: 'web-1', resourceType: 'grant', resourceId: 'g-1' })],
        nextCursor: null,
      });
    }),
  );
});

it('lists hook runs with exit, phase, command and output', async () => {
  const { user } = renderRoute('/o/acme/clients/cl-1/hooks');
  const runs = await screen.findByRole('list', { name: 'Hook runs' });
  const [ok, bad, refused, timedOut] = within(runs).getAllByRole('listitem');
  expect(within(ok!).getByText('0')).toBeInTheDocument();
  expect(within(ok!).getByText('/usr/sbin/nginx -s reload')).toBeInTheDocument();
  expect(within(bad!).getByText('2')).toBeInTheDocument();
  expect(within(bad!).getByText('1.4 s')).toBeInTheDocument();
  expect(within(refused!).getByText('Not run')).toBeInTheDocument();
  expect(within(refused!).getByText('Deleted hook')).toBeInTheDocument();
  expect(within(refused!).getByText('Pre-deploy')).toBeInTheDocument();
  expect(within(timedOut!).getByText('Timed out')).toBeInTheDocument();
  await user.click(within(bad!).getByRole('button', { name: 'Output of reload nginx' }));
  expect(within(bad!).getByLabelText('stderr')).toHaveTextContent('nginx: [emerg] bad config');
  expect(within(bad!).queryByLabelText('stdout')).not.toBeInTheDocument();
});

it('points an empty history at the grants tab', async () => {
  server.use(http.get(url('/orgs/org-1/clients/cl-1/hook-runs'), () => HttpResponse.json({ items: [], nextCursor: null })));
  const { user, router } = renderRoute('/o/acme/clients/cl-1/hooks');
  await user.click(await screen.findByRole('button', { name: 'Open certificates' }));
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/acme/clients/cl-1/certificates'));
});

it('shows audit events matching the client, including agent events', async () => {
  renderRoute('/o/acme/clients/cl-1/activity');
  const list = await screen.findByRole('list', { name: 'Client activity' });
  expect(auditQuery.get('q')).toBe('cl-1');
  expect(auditQuery.get('orgId')).toBe('org-1');
  expect(within(list).getByText('deployment.drift')).toBeInTheDocument();
  expect(within(list).getByText('web-1')).toBeInTheDocument();
  expect(screen.getByRole('link', { name: 'Open in audit log' })).toHaveAttribute('href', '/o/acme/audit?q=cl-1');
});

it('needs audit:read for activity', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  renderRoute('/o/acme/clients/cl-1/activity');
  expect(await screen.findByText('Needs the audit:read permission.')).toBeInTheDocument();
});
