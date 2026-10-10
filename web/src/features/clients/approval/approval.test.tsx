import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it, vi } from 'vitest';
import type { EnrollmentRequest } from '@/api/types';
import { server } from '@/test/server';
import { authHandlers, makeClient, makeEnrollmentRequest, makeSite, meWith, org, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';
import { formatVerifyCode } from './VerifyCode';

let requests: EnrollmentRequest[];
let approved: string[];
let rejected: string[];

beforeEach(() => {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(min-width: 768px)',
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
  requests = [makeEnrollmentRequest({ siteId: 's-1' })];
  approved = [];
  rejected = [];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/sites'), () => HttpResponse.json({ items: [makeSite({ id: 's-1', name: 'Rack A' })] })),
    http.get(url('/orgs/org-1/clients'), () => HttpResponse.json({ items: [makeClient({ id: 'cl-9', name: 'edge-1', status: 'pending' })], nextCursor: null })),
    http.get(url('/orgs/org-1/enrollment-requests'), () => HttpResponse.json({ items: requests })),
    http.post(url('/orgs/org-1/enrollment-requests/:id/approve'), ({ params }) => {
      approved.push(params.id as string);
      requests = [];
      return new HttpResponse(null, { status: 204 });
    }),
    http.post(url('/orgs/org-1/enrollment-requests/:id/reject'), ({ params }) => {
      rejected.push(params.id as string);
      requests = [];
      return new HttpResponse(null, { status: 204 });
    }),
  );
});

it('formats the code as ABCD-EFGH', () => {
  expect(formatVerifyCode('abcdefgh')).toBe('ABCD-EFGH');
  expect(formatVerifyCode('ABCD-EFGH')).toBe('ABCD-EFGH');
});

it('lists the request on Clients and shows the nav badge', async () => {
  renderRoute('/o/acme/clients');
  const card = await screen.findByRole('region', { name: 'Awaiting approval' });
  expect(within(card).getByText('edge-1.lan')).toBeInTheDocument();
  expect(within(card).getByText(/Token for edge-1/)).toBeInTheDocument();
  // The code is not on the row: the comparison happens in the dialog.
  expect(within(card).queryByText('ABCD-EFGH')).toBeNull();
  expect(await screen.findByRole('link', { name: /Clients, 1 awaiting approval/ })).toBeInTheDocument();
});

it('renders no queue and no badge when nothing is waiting', async () => {
  requests = [];
  renderRoute('/o/acme/clients');
  await screen.findByRole('table', { name: 'Clients' });
  expect(screen.queryByRole('region', { name: 'Awaiting approval' })).toBeNull();
  expect(screen.queryByRole('link', { name: /awaiting approval/ })).toBeNull();
});

it('hides the queue without clients:write', async () => {
  server.use(...authHandlers({ authed: true }), http.get(url('/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  renderRoute('/o/acme/clients');
  await screen.findByRole('table', { name: 'Clients' });
  expect(screen.queryByRole('region', { name: 'Awaiting approval' })).toBeNull();
});

it('keeps Approve blocked until the code is confirmed, then approves', async () => {
  const { user } = renderRoute('/o/acme/clients');
  await user.click(await screen.findByRole('button', { name: 'Review' }));
  const dialog = await screen.findByRole('dialog', { name: /Approve agent/ });
  expect(within(dialog).getByTestId('verify-code')).toHaveTextContent('ABCD-EFGH');
  expect(within(dialog).getByText('Verification code: A B C D E F G H')).toBeInTheDocument();
  expect(within(dialog).getByText('Rack A')).toBeInTheDocument();
  expect(within(dialog).queryByRole('textbox')).toBeNull();
  const approve = within(dialog).getByRole('button', { name: 'Approve' });
  expect(approve).toHaveAttribute('aria-disabled', 'true');
  await user.click(approve);
  expect(approved).toEqual([]);
  await user.click(within(dialog).getByRole('switch', { name: /Code matches/ }));
  const enabled = within(dialog).getByRole('button', { name: 'Approve' });
  expect(enabled).not.toHaveAttribute('aria-disabled');
  await user.click(enabled);
  await waitFor(() => expect(approved).toEqual(['er-1']));
  await waitFor(() => expect(screen.queryByRole('dialog')).toBeNull());
  await waitFor(() => expect(screen.queryByRole('region', { name: 'Awaiting approval' })).toBeNull());
});

it('rejects from the row after a confirmation', async () => {
  const { user } = renderRoute('/o/acme/clients');
  await user.click(await screen.findByRole('button', { name: 'Reject' }));
  const dialog = await screen.findByRole('dialog', { name: 'Reject enrolment from edge-1?' });
  expect(rejected).toEqual([]);
  await user.click(within(dialog).getByRole('button', { name: 'Reject' }));
  await waitFor(() => expect(rejected).toEqual(['er-1']));
});

it('swaps from the approve dialog to the reject dialog', async () => {
  const { user } = renderRoute('/o/acme/clients');
  await user.click(await screen.findByRole('button', { name: 'Review' }));
  await user.click(within(await screen.findByRole('dialog', { name: /Approve agent/ })).getByRole('button', { name: 'Reject' }));
  expect(await screen.findByRole('dialog', { name: /Reject enrolment/ })).toBeInTheDocument();
});

it('shows an inline message when someone else already handled the request', async () => {
  server.use(http.post(url('/orgs/org-1/enrollment-requests/:id/approve'), () => problem(409, 'already decided')));
  const { user } = renderRoute('/o/acme/clients');
  await user.click(await screen.findByRole('button', { name: 'Review' }));
  const dialog = await screen.findByRole('dialog', { name: /Approve agent/ });
  await user.click(within(dialog).getByRole('switch', { name: /Code matches/ }));
  await user.click(within(dialog).getByRole('button', { name: 'Approve' }));
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('Someone else already handled this request.');
});

it('an expired row offers Dismiss, not Review, and is not counted', async () => {
  requests = [makeEnrollmentRequest({ expiresAt: new Date(Date.now() - 1000).toISOString() })];
  const { user } = renderRoute('/o/acme/clients');
  const card = await screen.findByRole('region', { name: 'Awaiting approval' });
  expect(within(card).getByText('Expired')).toBeInTheDocument();
  expect(within(card).queryByRole('button', { name: 'Review' })).toBeNull();
  expect(screen.queryByRole('link', { name: /awaiting approval/ })).toBeNull();
  await user.click(within(card).getByRole('button', { name: 'Dismiss' }));
  await waitFor(() => expect(rejected).toEqual(['er-1']));
});

it('Enrol page: an enrolled agent shows Awaiting approval with Review', async () => {
  server.use(
    http.post(url('/orgs/org-1/clients'), () =>
      HttpResponse.json({ client: makeClient({ id: 'cl-9', name: 'edge-1', status: 'pending', online: false, connected: false }), token: 'cf1.x.y.z', expiresAt: new Date(Date.now() + 3_600_000).toISOString(), agentUrl: 'https://cf.lan:8443' }, { status: 201 }),
    ),
    http.get(url('/orgs/org-1/clients/cl-9'), () => HttpResponse.json(makeClient({ id: 'cl-9', name: 'edge-1', status: 'pending', online: false, connected: false }))),
  );
  const { user } = renderRoute('/o/acme/clients/new');
  await user.type(await screen.findByLabelText('Name'), 'edge-1');
  await user.click(screen.getByRole('button', { name: 'Create token' }));
  const panel = await screen.findByRole('region', { name: 'Agent connection' });
  expect(await within(panel).findByText('Agent enrolled. Awaiting approval.')).toBeInTheDocument();
  await user.click(within(panel).getByRole('button', { name: 'Review' }));
  expect(await screen.findByRole('dialog', { name: /Approve agent/ })).toBeInTheDocument();
});
