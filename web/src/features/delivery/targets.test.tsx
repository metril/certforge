import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, makeTarget, meWith, org, problem, traefikSchema, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let posted: unknown;
let deleted: string[];

beforeEach(() => {
  posted = undefined;
  deleted = [];
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema], notifiers: [], signers: [] })),
    http.get(url('/orgs/org-1/deploy-targets'), () =>
      HttpResponse.json({ items: [makeTarget({ grantCount: 2 }), makeTarget({ id: 't-2', name: 'spare', config: { dir: '/srv/traefik' }, grantCount: 0 })] }),
    ),
    http.post(url('/orgs/org-1/deploy-targets'), async ({ request }) => {
      posted = await request.json();
      return HttpResponse.json(makeTarget({ id: 't-3' }), { status: 201 });
    }),
    http.delete(url('/orgs/org-1/deploy-targets/:id'), ({ params }) => {
      deleted.push(params.id as string);
      return new HttpResponse(null, { status: 204 });
    }),
  );
});

const rowOf = (name: string) => screen.getByText(name, { selector: 'td' }).closest('tr')!;

it('opens from the nav and lists targets with type, directory and use', async () => {
  const { router } = renderRoute('/o/acme/delivery');
  await screen.findByRole('table', { name: 'Deploy targets' });
  expect(router.state.location.pathname).toBe('/o/acme/delivery/targets');
  const row = rowOf('edge traefik');
  for (const text of ['Traefik (file provider)', 'Agent', '/etc/traefik/dynamic', '2 grants']) expect(within(row).getByText(text)).toBeInTheDocument();
  expect(within(rowOf('spare')).getByText('–')).toBeInTheDocument();
});

it('adds a Traefik target from its schema form', async () => {
  const { user, router } = renderRoute('/o/acme/delivery/targets');
  await user.click(await screen.findByRole('button', { name: 'Add target' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  await user.type(within(sheet).getByLabelText('Name'), 'edge-2');
  await user.type(within(sheet).getByLabelText('Directory on the agent'), '/etc/traefik/dynamic');
  await user.click(within(sheet).getByRole('switch', { name: 'Default certificate' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(posted).toMatchObject({ name: 'edge-2', type: 'traefik', config: { dir: '/etc/traefik/dynamic', defaultCert: true } }));
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('edit'));
});

it('refuses a relative directory before sending', async () => {
  const { user } = renderRoute('/o/acme/delivery/targets?edit=new');
  const sheet = await screen.findByRole('dialog', { name: 'Add deploy target' });
  await user.type(within(sheet).getByLabelText('Name'), 'bad');
  await user.type(within(sheet).getByLabelText('Directory on the agent'), 'traefik');
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await new Promise((r) => setTimeout(r, 50));
  expect(screen.getByRole('dialog', { name: 'Add deploy target' })).toBeInTheDocument();
  expect(posted).toBeUndefined();
});

it('blocks deleting a target in use and deletes an unused one by name', async () => {
  const { user } = renderRoute('/o/acme/delivery/targets');
  await screen.findByRole('table', { name: 'Deploy targets' });
  expect(screen.getByRole('button', { name: 'Delete edge traefik' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'Delete spare' }));
  await user.type(screen.getByLabelText(/to confirm/), 'spare');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  await waitFor(() => expect(deleted).toEqual(['t-2']));
});

it('shows a raced 409 inside the delete dialog', async () => {
  server.use(http.delete(url('/orgs/org-1/deploy-targets/:id'), () => problem(409, 'Used by web-1/www.')));
  const { user } = renderRoute('/o/acme/delivery/targets');
  await user.click(await screen.findByRole('button', { name: 'Delete spare' }));
  await user.type(screen.getByLabelText(/to confirm/), 'spare');
  await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: 'Delete' }));
  expect(await within(screen.getByRole('dialog')).findByText('Used by web-1/www.')).toBeInTheDocument();
});

it('is read-only for a viewer', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'viewer', orgId: org.id }]))));
  const { user } = renderRoute('/o/acme/delivery/targets');
  expect(await screen.findByRole('button', { name: 'Add target' })).toBeDisabled();
  await user.click(screen.getByRole('button', { name: 'View edge traefik' }));
  const sheet = await screen.findByRole('dialog', { name: 'edge traefik' });
  expect(within(sheet).getByLabelText('Name')).toBeDisabled();
  expect(within(sheet).queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
});

it('is not available under All orgs', async () => {
  const { router } = renderRoute('/o/all/delivery/targets');
  await waitFor(() => expect(router.state.location.pathname).toBe('/o/all/overview'));
});
