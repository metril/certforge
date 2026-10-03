import { delay, http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, me, meWith, org, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

const general = { section: 'general', schema: { type: 'object', properties: {} }, value: {}, stored: null, storedSecrets: [] };
const base = [
  http.get(url('/settings/general'), () => HttpResponse.json(general)),
  http.get(url('/orgs'), () => HttpResponse.json({ items: [org] })),
  http.get(url('/orgs/:orgId/sites'), () => HttpResponse.json({ items: [{ id: 's-1', orgId: org.id, name: 'Berlin', createdAt: '2026-09-01T00:00:00Z' }] })),
];

it('creates an org with a slug derived from the name', async () => {
  let body: unknown;
  server.use(...authHandlers({ authed: true }), ...base,
    http.post(url('/orgs'), async ({ request }) => { body = await request.json(); return HttpResponse.json({ id: 'org-3', slug: 'lab-two', name: 'Lab Two' }, { status: 201 }); }));
  const { user } = renderRoute('/settings/general');
  await user.click(await screen.findByRole('button', { name: 'New organization' }));
  const sheet = await screen.findByRole('dialog', { name: 'New organization' });
  await user.type(within(sheet).getByLabelText('Name'), 'Lab Two');
  expect(within(sheet).getByLabelText('Slug')).toHaveValue('lab-two');
  await user.click(within(sheet).getByRole('button', { name: 'Create' }));
  expect(body).toEqual({ slug: 'lab-two', name: 'Lab Two' });
});

it('refuses the reserved slug', async () => {
  server.use(...authHandlers({ authed: true }), ...base);
  const { user } = renderRoute('/settings/general');
  await user.click(await screen.findByRole('button', { name: 'New organization' }));
  const sheet = await screen.findByRole('dialog', { name: 'New organization' });
  await user.type(within(sheet).getByLabelText('Name'), 'Everything');
  const slug = within(sheet).getByLabelText('Slug');
  await user.clear(slug);
  await user.type(slug, 'all');
  expect(within(sheet).getByText('"all" is reserved.')).toBeInTheDocument();
  expect(within(sheet).getByRole('button', { name: 'Create' })).toBeDisabled();
});

it('shows the dependents that block a delete', async () => {
  server.use(...authHandlers({ authed: true }), ...base,
    http.delete(url('/orgs/:orgId'), () => problem(409, 'Delete these first: 2 certificates, 1 DNS credential.', {}, 'Conflict')));
  const { user } = renderRoute('/settings/general');
  await user.click(await screen.findByRole('button', { name: 'Delete Acme' }));
  const dialog = await screen.findByRole('dialog', { name: 'Delete Acme' });
  await user.type(within(dialog).getByRole('textbox'), 'acme');
  await user.click(within(dialog).getByRole('button', { name: 'Delete' }));
  expect(await within(dialog).findByText(/2 certificates, 1 DNS credential/)).toBeInTheDocument();
});

it('navigates to / and refreshes Me after deleting the active org', async () => {
  let meCalls = 0;
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => {
      meCalls += 1;
      return HttpResponse.json(meCalls === 1 ? me : meWith([{ role: 'admin', orgId: null }], []));
    }),
    ...base,
    http.delete(url('/orgs/:orgId'), () => new HttpResponse(null, { status: 204 })),
  );
  const { user } = renderRoute('/settings/general');
  await user.click(await screen.findByRole('button', { name: 'Delete Acme' }));
  const dialog = await screen.findByRole('dialog', { name: 'Delete Acme' });
  await user.type(within(dialog).getByRole('textbox'), 'acme');
  await user.click(within(dialog).getByRole('button', { name: 'Delete' }));
  expect(await screen.findByText('No organization exists for your account yet.')).toBeInTheDocument();
  expect(meCalls).toBeGreaterThanOrEqual(2);
});

it('keeps a manually edited slug when the name keeps changing', async () => {
  server.use(...authHandlers({ authed: true }), ...base);
  const { user } = renderRoute('/settings/general');
  await user.click(await screen.findByRole('button', { name: 'New organization' }));
  const sheet = await screen.findByRole('dialog', { name: 'New organization' });
  const slug = within(sheet).getByLabelText('Slug');
  await user.type(within(sheet).getByLabelText('Name'), 'Lab');
  await user.clear(slug);
  await user.type(slug, 'custom-slug');
  await user.type(within(sheet).getByLabelText('Name'), ' Two');
  expect(slug).toHaveValue('custom-slug');
});

it('shows a fetch error in the sites sheet', async () => {
  server.use(...authHandlers({ authed: true }),
    http.get(url('/settings/general'), () => HttpResponse.json(general)),
    http.get(url('/orgs'), () => HttpResponse.json({ items: [org] })),
    http.get(url('/orgs/:orgId/sites'), () => problem(500, 'Could not load sites.')));
  const { user } = renderRoute('/settings/general');
  await user.click(await screen.findByRole('button', { name: 'Sites of Acme' }));
  const sheet = await screen.findByRole('dialog', { name: 'Sites of Acme' });
  expect(await within(sheet).findByRole('alert')).toHaveTextContent('Could not load sites.');
});

it('shows an inline error for a duplicate site name', async () => {
  server.use(...authHandlers({ authed: true }), ...base,
    http.post(url('/orgs/:orgId/sites'), () => problem(409, 'Site name already used.', {}, 'Conflict')));
  const { user } = renderRoute('/settings/general');
  await user.click(await screen.findByRole('button', { name: 'Sites of Acme' }));
  const sheet = await screen.findByRole('dialog', { name: 'Sites of Acme' });
  await user.type(within(sheet).getByLabelText('New site'), 'Berlin');
  await user.click(within(sheet).getByRole('button', { name: 'Add' }));
  expect(await within(sheet).findByText('Site name already used.')).toBeInTheDocument();
});

it('manages sites', async () => {
  const calls: string[] = [];
  server.use(...authHandlers({ authed: true }), ...base,
    http.post(url('/orgs/:orgId/sites'), async ({ request }) => { calls.push(`POST ${JSON.stringify(await request.json())}`); return HttpResponse.json({ id: 's-2', orgId: org.id, name: 'Paris', createdAt: '2026-09-01T00:00:00Z' }, { status: 201 }); }),
    http.patch(url('/orgs/:orgId/sites/:id'), async ({ request, params }) => { calls.push(`PATCH ${params.id} ${JSON.stringify(await request.json())}`); return HttpResponse.json({ id: 's-1', orgId: org.id, name: 'Berlin HQ', createdAt: '2026-09-01T00:00:00Z' }); }));
  const { user } = renderRoute('/settings/general');
  await user.click(await screen.findByRole('button', { name: 'Sites of Acme' }));
  const sheet = await screen.findByRole('dialog', { name: 'Sites of Acme' });
  expect(await within(sheet).findByText('Berlin')).toBeInTheDocument();
  await user.type(within(sheet).getByLabelText('New site'), 'Paris');
  await user.click(within(sheet).getByRole('button', { name: 'Add' }));
  await user.click(within(sheet).getByRole('button', { name: 'Rename Berlin' }));
  const input = within(sheet).getByLabelText('Name of Berlin');
  await user.clear(input);
  await user.type(input, 'Berlin HQ{Enter}');
  expect(calls).toEqual(['POST {"name":"Paris"}', 'PATCH s-1 {"name":"Berlin HQ"}']);
});

it('disables the rename Save button while the rename is pending', async () => {
  server.use(...authHandlers({ authed: true }), ...base,
    http.patch(url('/orgs/:orgId/sites/:id'), async () => { await delay(300); return HttpResponse.json({ id: 's-1', orgId: org.id, name: 'Berlin HQ', createdAt: '2026-09-01T00:00:00Z' }); }));
  const { user } = renderRoute('/settings/general');
  await user.click(await screen.findByRole('button', { name: 'Sites of Acme' }));
  const sheet = await screen.findByRole('dialog', { name: 'Sites of Acme' });
  await user.click(await within(sheet).findByRole('button', { name: 'Rename Berlin' }));
  const input = within(sheet).getByLabelText('Name of Berlin');
  await user.type(input, ' HQ');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(within(sheet).getByRole('button', { name: 'Save' })).toBeDisabled();
  await waitFor(() => expect(within(sheet).queryByLabelText('Name of Berlin')).not.toBeInTheDocument());
});

it('hides org writes from non-admins', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))),
    ...base,
  );
  renderRoute('/settings/general');
  expect(await screen.findByRole('button', { name: 'Sites of Acme' })).toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'New organization' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Rename Acme' })).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Delete Acme' })).not.toBeInTheDocument();
});
