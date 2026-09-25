import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { server } from '@/test/server';
import { adminUser, annUser, authHandlers, makeBinding, meWith, org, problem, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

const list = [makeBinding(), makeBinding({ id: 'rb-2', subjectType: 'oidc_group', subject: 'ops', subjectLabel: 'ops', role: 'operator', orgId: null })];

function handlers(onPost?: (b: unknown) => Response | undefined) {
  return [
    http.get(url('/role-bindings'), () => HttpResponse.json({ items: list })),
    http.get(url('/users'), () => HttpResponse.json({ items: [adminUser, annUser] })),
    http.get(url('/api-keys'), () => HttpResponse.json({ items: [] })),
    http.post(url('/role-bindings'), async ({ request }) => {
      const body = await request.json();
      return onPost?.(body) ?? HttpResponse.json(makeBinding({ id: 'rb-3' }), { status: 201 });
    }),
  ];
}

// Desktop by default (D5 mobile-card test overrides this), mirroring
// UsersTab's users.test.tsx viewport stub.
function stubViewport(isMdUp: boolean) {
  vi.stubGlobal('matchMedia', (query: string) => ({
    matches: query === '(min-width: 768px)' ? isMdUp : false,
    media: query,
    addEventListener: () => {},
    removeEventListener: () => {},
  }));
}
const ORIGINAL_INNER_WIDTH = window.innerWidth;
beforeEach(() => {
  stubViewport(true);
});
afterEach(() => {
  vi.unstubAllGlobals();
  window.innerWidth = ORIGINAL_INNER_WIDTH;
});

it('lists bindings with subject, role and scope', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  renderRoute('/settings/access?tab=bindings');
  const table = await screen.findByRole('table', { name: 'Role bindings' });
  expect(await within(table).findByText('Ann')).toBeInTheDocument();
  expect(within(table).getByText('Acme')).toBeInTheDocument();
  expect(within(table).getByText('ops')).toBeInTheDocument();
  expect(within(table).getByText('All orgs')).toBeInTheDocument();
});

it('adds a group binding', async () => {
  let body: unknown;
  server.use(...authHandlers({ authed: true }), ...handlers((b) => { body = b; return undefined; }));
  const { user } = renderRoute('/settings/access?tab=bindings');
  await user.click(await screen.findByRole('button', { name: 'Add binding' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add binding' });
  await user.click(within(sheet).getByRole('radio', { name: 'Group' }));
  await user.type(within(sheet).getByLabelText('Group'), 'ops');
  await user.click(within(sheet).getByRole('radio', { name: 'Operator' }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(body).toEqual({ subjectType: 'oidc_group', subject: 'ops', role: 'operator', orgId: org.id }));
});

it('says so when the binding already exists', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers(() => problem(409, 'This binding already exists.', {}, 'Conflict')));
  const { user } = renderRoute('/settings/access?tab=bindings');
  await user.click(await screen.findByRole('button', { name: 'Add binding' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add binding' });
  await user.click(within(sheet).getByRole('combobox', { name: 'User' }));
  await user.click(await screen.findByRole('option', { name: /Ann/ }));
  await user.click(within(sheet).getByRole('button', { name: 'Save' }));
  expect(await within(sheet).findByRole('alert')).toHaveTextContent('This binding already exists.');
});

it('offers All orgs only to global binding writers', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: org.id }]))),
    ...handlers(),
  );
  const { user } = renderRoute('/settings/access?tab=bindings');
  await user.click(await screen.findByRole('button', { name: 'Add binding' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add binding' });
  await user.click(within(sheet).getByRole('combobox', { name: 'Scope' }));
  expect(await screen.findByRole('option', { name: 'Acme' })).toBeInTheDocument();
  expect(screen.queryByRole('option', { name: 'All orgs' })).not.toBeInTheDocument();
});

// Controller ruling: oidc_group bindings always need GLOBAL bindings:write,
// so an org-admin (no global binding) sees the Group segment disabled with
// a tooltip rather than able to create a group mapping in their own org.
it('disables the Group subject type for an org-admin with no global binding', async () => {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: org.id }]))),
    ...handlers(),
  );
  const { user } = renderRoute('/settings/access?tab=bindings');
  await user.click(await screen.findByRole('button', { name: 'Add binding' }));
  const sheet = await screen.findByRole('dialog', { name: 'Add binding' });
  const group = within(sheet).getByRole('radio', { name: 'Group' });
  expect(group).toHaveAttribute('data-disabled');
  await user.hover(group);
  expect(await screen.findByText('Only a global admin can add group mappings.')).toBeInTheDocument();
});

it('removes a binding after typing the subject', async () => {
  let deleted = '';
  server.use(...authHandlers({ authed: true }), ...handlers(),
    http.delete(url('/role-bindings/:id'), ({ params }) => { deleted = String(params.id); return new HttpResponse(null, { status: 204 }); }));
  const { user } = renderRoute('/settings/access?tab=bindings');
  const table = await screen.findByRole('table', { name: 'Role bindings' });
  await user.click(await within(table).findByRole('button', { name: 'Remove Ann viewer' }));
  const dialog = await screen.findByRole('dialog');
  await user.type(within(dialog).getByRole('textbox'), 'Ann');
  await user.click(within(dialog).getByRole('button', { name: 'Remove' }));
  await waitFor(() => expect(deleted).toBe('rb-1'));
});

// Controller ruling: deleting the last enabled global admin's binding
// returns 409; the confirm dialog shows the problem detail inline and
// stays open (ConfirmDestructive's default error handling), same contract
// as UsersTab's own last-admin 409 test.
it('shows a 409 inline and keeps the remove dialog open', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers(),
    http.delete(url('/role-bindings/:id'), () => problem(409, 'Cannot remove the last global admin.')));
  const { user } = renderRoute('/settings/access?tab=bindings');
  const table = await screen.findByRole('table', { name: 'Role bindings' });
  await user.click(await within(table).findByRole('button', { name: 'Remove Ann viewer' }));
  const dialog = await screen.findByRole('dialog');
  await user.type(within(dialog).getByRole('textbox'), 'Ann');
  await user.click(within(dialog).getByRole('button', { name: 'Remove' }));
  expect(await within(dialog).findByRole('alert')).toHaveTextContent('Cannot remove the last global admin.');
  expect(screen.getByRole('dialog')).toBeInTheDocument();
});

// D5: card rows below 768px, no horizontal overflow at 375px.
it('shows card rows instead of a table below 768px with no horizontal overflow', async () => {
  stubViewport(false);
  window.innerWidth = 375;
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { container } = renderRoute('/settings/access?tab=bindings');
  await screen.findByText('Ann');
  expect(screen.queryByRole('table')).toBeNull();
  expect(screen.getByText('ops')).toBeInTheDocument();
  const cardsRoot = screen.getByText('Ann').closest('.grid.gap-2')!.parentElement!;
  expect(cardsRoot.className).not.toMatch(/min-w-\[/);
  expect(container.querySelector('[class*="min-w-["]')).toBeNull();
  expect(document.documentElement.scrollWidth).toBeLessThanOrEqual(window.innerWidth);
});

it('filters bindings by subject type, synced to the URL', async () => {
  server.use(...authHandlers({ authed: true }), ...handlers());
  const { user, router } = renderRoute('/settings/access?tab=bindings');
  await screen.findByRole('table', { name: 'Role bindings' });
  await user.click(screen.getByRole('radio', { name: 'Groups' }));
  await waitFor(() => expect(router.state.location.search).toMatchObject({ type: 'oidc_group' }));
});
