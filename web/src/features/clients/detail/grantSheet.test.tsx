import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeEach, expect, it } from 'vitest';
import { help } from '@/lib/help';
import { server } from '@/test/server';
import { authHandlers, makeCert, makeClient, makeGrant, makeHook, makeLayout, makeTarget, meWith, org, problem, targetVaultKv, traefikSchema, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

let posted: { certificateId: string }[];
let patched: unknown;

beforeEach(() => {
  posted = [];
  patched = undefined;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/clients/cl-1'), () => HttpResponse.json(makeClient())),
    http.get(url('/orgs/org-1/clients/cl-1/grants'), () => HttpResponse.json({ items: [makeGrant({ id: 'g-1', certificateId: 'c-1', certificateName: 'www' })] })),
    http.get(url('/orgs/org-1/certificates'), () =>
      HttpResponse.json({
        items: [makeCert({ id: 'c-1', name: 'www' }), makeCert({ id: 'c-2', name: 'api', commonName: 'api.example.com' }), makeCert({ id: 'c-3', name: 'mail', commonName: 'mail.example.com' })],
        nextCursor: null,
      }),
    ),
    http.get(url('/orgs/org-1/layouts'), () => HttpResponse.json({ items: [makeLayout()] })),
    http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [makeTarget()] })),
    http.get(url('/orgs/org-1/hooks'), () => HttpResponse.json({ items: [makeHook()] })),
    http.get(url('/meta/schemas'), () => HttpResponse.json({ dnsProviders: [], deployTargets: [traefikSchema], notifiers: [], signers: [] })),
    http.post(url('/orgs/org-1/clients/cl-1/grants'), async ({ request }) => {
      const body = (await request.json()) as { certificateId: string };
      posted.push(body);
      return HttpResponse.json(makeGrant({ id: `g-${body.certificateId}`, certificateId: body.certificateId }), { status: 201 });
    }),
    http.patch(url('/orgs/org-1/grants/g-1'), async ({ request }) => {
      patched = await request.json();
      return HttpResponse.json(makeGrant());
    }),
  );
});

type User = ReturnType<typeof renderRoute>['user'];

// An option's accessible name includes its hint ("apiapi.example.com",
// "nginx1 file", "edge traefikTraefik (file provider)"), so match the start.
async function pick(user: User, combobox: string, option: RegExp) {
  await user.click(await screen.findByRole('combobox', { name: combobox }));
  await user.click(await screen.findByRole('option', { name: option }));
}

/** The multi-lookup stays open while picking; `absent` must not be offered.
 * Certificates renders behind `QueryField` (M2), so its combobox appears
 * only once the certificates list has actually loaded. */
async function pickMany(user: User, options: RegExp[], absent?: RegExp) {
  await user.click(await screen.findByRole('combobox', { name: 'Certificates' }));
  for (const o of options) await user.click(await screen.findByRole('option', { name: o }));
  if (absent) expect(screen.queryByRole('option', { name: absent })).not.toBeInTheDocument();
  await user.keyboard('{Escape}');
}

it('shows an inline error with retry when certificates fail to load', async () => {
  let calls = 0;
  server.use(
    http.get(url('/orgs/org-1/certificates'), () => {
      calls += 1;
      return calls === 1 ? problem(500, 'boom') : HttpResponse.json({ items: [makeCert({ id: 'c-1', name: 'www' })], nextCursor: null });
    }),
  );
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates?grant=new');
  const sheet = await screen.findByRole('dialog', { name: 'Grant certificate' });
  expect(await within(sheet).findByText("Couldn't load certificates. boom")).toBeInTheDocument();
  await user.click(within(sheet).getByRole('button', { name: 'Retry' }));
  await waitFor(() => expect(within(sheet).getByRole('combobox', { name: 'Certificates' })).toBeInTheDocument());
});

it('grants several certificates with one layout and closes', async () => {
  const { user, router } = renderRoute('/o/acme/clients/cl-1/certificates');
  await user.click(await screen.findByRole('button', { name: 'Grant certificate' }));
  const sheet = await screen.findByRole('dialog', { name: 'Grant certificate' });
  await pickMany(user, [/^api/, /^mail/], /^www/);
  await pick(user, 'Layout', /^nginx/);
  await user.click(within(sheet).getByRole('button', { name: 'Advanced' }));
  await user.click(within(sheet).getByRole('button', { name: 'reload nginx' }));
  await user.click(within(sheet).getByRole('switch', { name: 'Auto-remediate' }));
  await user.click(within(sheet).getByRole('button', { name: 'Grant' }));
  await waitFor(() => expect(screen.queryByRole('dialog', { name: 'Grant certificate' })).not.toBeInTheDocument());
  expect(posted).toEqual([
    { certificateId: 'c-2', delivery: 'push', layoutId: 'l-1', deployTargetId: null, hookIds: ['h-1'], autoRemediate: true },
    { certificateId: 'c-3', delivery: 'push', layoutId: 'l-1', deployTargetId: null, hookIds: ['h-1'], autoRemediate: true },
  ]);
  expect(router.state.location.search).not.toHaveProperty('grant');
});

it('requires a certificate and a layout or target', async () => {
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates?grant=new');
  const sheet = await screen.findByRole('dialog', { name: 'Grant certificate' });
  await user.click(within(sheet).getByRole('button', { name: 'Grant' }));
  expect(within(sheet).getByText('Pick at least one certificate.')).toBeInTheDocument();
  expect(within(sheet).getByText('Pick a layout, a deploy target, or both.')).toBeInTheDocument();
  expect(posted).toEqual([]);
});

it('partial failure: keeps the failed certificate selected with its reason', async () => {
  server.use(
    http.post(url('/orgs/org-1/clients/cl-1/grants'), async ({ request }) => {
      const body = (await request.json()) as { certificateId: string };
      posted.push(body);
      if (body.certificateId === 'c-2') return problem(409, 'api is already granted to web-1.');
      return HttpResponse.json(makeGrant({ id: `g-${body.certificateId}` }), { status: 201 });
    }),
  );
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates?grant=new');
  const sheet = await screen.findByRole('dialog', { name: 'Grant certificate' });
  await pickMany(user, [/^api/, /^mail/]);
  await pick(user, 'Deploy target', /^edge traefik/);
  await user.click(within(sheet).getByRole('button', { name: 'Grant' }));
  expect(await within(sheet).findByText('api: api is already granted to web-1.')).toBeInTheDocument();
  const chips = within(sheet).getByRole('list', { name: 'Selected certificates' });
  expect(within(chips).getAllByRole('listitem').map((li) => li.textContent)).toEqual(['api']);
  expect(posted.map((p) => p.certificateId)).toEqual(['c-2', 'c-3']);
});

it('warns about no push while delivery is pull', async () => {
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates?grant=new');
  const sheet = await screen.findByRole('dialog', { name: 'Grant certificate' });
  expect(within(sheet).queryByText('No push')).not.toBeInTheDocument();
  await user.click(within(sheet).getByRole('radio', { name: 'Pull' }));
  expect(within(sheet).getByText('No push')).toBeInTheDocument();
  await user.click(within(sheet).getByRole('radio', { name: 'Push' }));
  expect(within(sheet).queryByText('No push')).not.toBeInTheDocument();
});

it('shows a 409 on save with the failed tone and keeps the sheet open', async () => {
  server.use(http.patch(url('/orgs/org-1/grants/g-1'), () => problem(409, 'The path collides with another grant.')));
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates?grant=g-1');
  const sheet = await screen.findByRole('dialog', { name: 'Edit www' });
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  const message = await within(sheet).findByText('The path collides with another grant.');
  expect(message.closest('[role="alert"]')).toHaveClass('text-failed');
  expect(screen.getByRole('dialog', { name: 'Edit www' })).toBeInTheDocument();
});

it('clears an unknown grant id from the url and notifies', async () => {
  const { router } = renderRoute('/o/acme/clients/cl-1/certificates?grant=nope-1');
  await screen.findByText('Grant not found.');
  await waitFor(() => expect(router.state.location.search).not.toHaveProperty('grant'));
  expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
});

it('edits a grant with every field sent', async () => {
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates?grant=g-1');
  const sheet = await screen.findByRole('dialog', { name: 'Edit www' });
  await user.click(within(sheet).getByRole('radio', { name: 'Pull' }));
  await pick(user, 'Deploy target', /^edge traefik/);
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toEqual({ delivery: 'pull', layoutId: 'l-1', deployTargetId: 't-1', hookIds: [], autoRemediate: false }));
});

it('shows hooks in run order and saves the reordered list', async () => {
  server.use(
    http.get(url('/orgs/org-1/hooks'), () => HttpResponse.json({ items: [makeHook(), makeHook({ id: 'h-2', name: 'notify', phase: 'pre_deploy' })] })),
    http.get(url('/orgs/org-1/clients/cl-1/grants'), () =>
      HttpResponse.json({ items: [makeGrant({ id: 'g-1', certificateId: 'c-1', certificateName: 'www', hookIds: ['h-1', 'h-2'] })] }),
    ),
  );
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates?grant=g-1');
  const sheet = await screen.findByRole('dialog', { name: 'Edit www' });
  await user.click(await within(sheet).findByRole('button', { name: /^Advanced/ }));
  await within(sheet).findByRole('list', { name: 'Hook run order' });
  const order = () => within(within(sheet).getByRole('list', { name: 'Hook run order' })).getAllByRole('listitem').map((li) => li.textContent);
  expect(order()).toEqual([expect.stringMatching(/^1\.reload nginx/), expect.stringMatching(/^2\.notify/)]);
  expect(within(sheet).getByRole('button', { name: 'Move reload nginx up' })).toHaveAttribute('aria-disabled', 'true');
  await user.click(within(sheet).getByRole('button', { name: 'Move notify up' }));
  expect(order()).toEqual([expect.stringMatching(/^1\.notify/), expect.stringMatching(/^2\.reload nginx/)]);
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(patched).toMatchObject({ hookIds: ['h-2', 'h-1'] }));
});

// Task 8: a server-run target (vault-kv) is never grantable to a client;
// it shows disabled with a tooltip, never hidden (Deviation 5A R9/R6).
it('shows a server-run target disabled in the deploy target picker', async () => {
  server.use(http.get(url('/orgs/org-1/deploy-targets'), () => HttpResponse.json({ items: [makeTarget(), targetVaultKv] })));
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates?grant=new');
  const sheet = await screen.findByRole('dialog', { name: 'Grant certificate' });
  await user.click(await within(sheet).findByRole('combobox', { name: 'Deploy target' }));
  const opt = await screen.findByRole('option', { name: new RegExp(`^${targetVaultKv.name}`) });
  expect(opt).toHaveAttribute('aria-disabled', 'true');
  await user.hover(opt);
  expect(await screen.findByRole('tooltip')).toHaveTextContent(help['grant.serverTarget'].text);
  await user.click(opt);
  expect(screen.getByRole('combobox', { name: 'Deploy target' })).toBeInTheDocument();
});

it('disables Grant with a keys:export tooltip when the pick hands the agent a key', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'operator', orgId: org.id }]))));
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates?grant=new');
  const sheet = await screen.findByRole('dialog', { name: 'Grant certificate' });
  await pick(user, 'Layout', /^nginx/);
  expect(within(sheet).getByRole('button', { name: 'Grant' })).toBeEnabled();
  await pick(user, 'Deploy target', /^edge traefik/);
  const grant = within(sheet).getByRole('button', { name: 'Grant' });
  expect(grant).toBeDisabled();
  await user.hover(grant.parentElement!);
  expect(await screen.findByRole('tooltip')).toHaveTextContent('Needs the keys:export permission');
});

it('lets an admin grant a deploy target', async () => {
  const { user } = renderRoute('/o/acme/clients/cl-1/certificates?grant=new');
  const sheet = await screen.findByRole('dialog', { name: 'Grant certificate' });
  await pick(user, 'Deploy target', /^edge traefik/);
  expect(within(sheet).getByRole('button', { name: 'Grant' })).toBeEnabled();
});

it('keeps the sheet open with a removed notice when the grant disappears', async () => {
  const { user, queryClient } = renderRoute('/o/acme/clients/cl-1/certificates?grant=g-1');
  await screen.findByRole('dialog', { name: 'Edit www' });
  server.use(http.get(url('/orgs/org-1/clients/cl-1/grants'), () => HttpResponse.json({ items: [] })));
  await queryClient.invalidateQueries({ queryKey: ['grants'] });
  const sheet = await screen.findByRole('dialog', { name: 'Edit www' });
  expect(await within(sheet).findByText(/This grant was removed/)).toBeInTheDocument();
  expect(within(sheet).getByRole('button', { name: 'Save' })).toBeDisabled();
  await user.hover(within(sheet).getByRole('button', { name: 'Save' }));
  expect(await screen.findByRole('tooltip')).toHaveTextContent('This grant was removed');
  await user.click(within(sheet).getByRole('button', { name: 'Cancel' }));
  await waitFor(() => expect(screen.queryByRole('dialog')).not.toBeInTheDocument());
});
