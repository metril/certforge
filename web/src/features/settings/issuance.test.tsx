import { http, HttpResponse } from 'msw';
import { screen, waitFor, within } from '@testing-library/react';
import { beforeAll, beforeEach, expect, it } from 'vitest';
import { server } from '@/test/server';
import { authHandlers, meWith, org, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

// Task 9: the global-only `issuance` settings section (CAA check + local
// rate limits) rendered from its own JSON Schema (`issuanceSettingsSchema`,
// server.ts's default `/settings/issuance` GET handler) via `SchemaSection`,
// under IssuanceDefaultsSection's Global tab only.
beforeAll(async () => {
  await import('./SettingsPage');
});

let issuancePut: Record<string, unknown> | undefined;

beforeEach(() => {
  issuancePut = undefined;
  server.use(
    ...authHandlers({ authed: true }),
    http.get(url('/orgs/org-1/cas'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/acme-accounts'), () => HttpResponse.json([])),
    http.get(url('/orgs/org-1/dns-credentials'), () => HttpResponse.json([])),
    http.get(url('/settings/issuance_defaults'), () => HttpResponse.json({ schema: {}, value: {}, stored: null })),
    http.get(url('/orgs/org-1/issuance-defaults'), () => HttpResponse.json({})),
    http.get(url('/orgs/org-1/issuance-defaults/effective'), () => HttpResponse.json({})),
    http.put(url('/settings/issuance'), async ({ request }) => {
      issuancePut = (await request.json()) as Record<string, unknown>;
      return HttpResponse.json({});
    }),
  );
});

async function openGlobalTab() {
  const { user, ...rest } = renderRoute('/settings/issuance-defaults');
  await user.click(await screen.findByRole('tab', { name: 'Global' }));
  await screen.findByText('Checks and limits');
  return { user, ...rest };
}

it('renders the CAA switch and the four rate limits from the schema', async () => {
  await openGlobalTab();
  expect(screen.getByRole('switch', { name: 'Check CAA records' })).toBeChecked();
  expect(screen.getByLabelText('Certificates per registered domain per week')).toHaveValue(50);
  expect(screen.getByLabelText('Duplicate certificates per week')).toHaveValue(5);
  expect(screen.getByLabelText('Failed validations per hour')).toHaveValue(5);
  expect(screen.getByLabelText('New orders per 3 hours')).toHaveValue(300);
});

// B5: the limits grid must carry `sm:grid-cols-2` on the object's own
// wrapper (ObjectFieldTemplate), not on the label-and-content wrapper a
// leaf FieldTemplate would apply it to.
it('the limits grid gets the two-column class', async () => {
  const { container } = await openGlobalTab();
  const grid = container.querySelector('[class*="sm:grid-cols-2"]');
  expect(grid).toBeInTheDocument();
  expect(within(grid as HTMLElement).getByLabelText('Duplicate certificates per week')).toBeInTheDocument();
});

it('saves the section: toggling CAA off and editing one limit PUTs the whole section', async () => {
  const { user } = await openGlobalTab();
  await user.click(screen.getByRole('switch', { name: 'Check CAA records' }));
  const duplicates = screen.getByLabelText('Duplicate certificates per week');
  await user.clear(duplicates);
  await user.type(duplicates, '10');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() =>
    expect(issuancePut).toEqual({
      caaCheck: false,
      rateLimits: { certsPerRegisteredDomainPerWeek: 50, duplicateCertsPerWeek: 10, failedValidationsPerHour: 5, newOrdersPer3Hours: 300 },
    }),
  );
});

it('0 is allowed; -1 is blocked by the inline schema error and never reaches the PUT', async () => {
  const { user } = await openGlobalTab();
  const failed = screen.getByLabelText('Failed validations per hour');
  await user.clear(failed);
  await user.type(failed, '0');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  await waitFor(() => expect(issuancePut).toMatchObject({ rateLimits: { failedValidationsPerHour: 0 } }));

  issuancePut = undefined;
  await user.clear(failed);
  await user.type(failed, '-1');
  await user.click(screen.getByRole('button', { name: 'Save' }));
  expect(await screen.findByRole('alert')).toHaveTextContent('Must be at least 0.');
  expect(issuancePut).toBeUndefined();
});

it('an org admin (no global settings:write) sees it read-only with no Save', async () => {
  server.use(http.get(url('/auth/me'), () => HttpResponse.json(meWith([{ role: 'org-admin', orgId: org.id }]))));
  await openGlobalTab();
  expect(screen.getByRole('switch', { name: 'Check CAA records' })).toBeDisabled();
  expect(screen.getByLabelText('Duplicate certificates per week')).toBeDisabled();
  expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument();
});

it('the org tab has no checks-and-limits block', async () => {
  renderRoute('/settings/issuance-defaults');
  await screen.findByRole('tab', { name: 'Global' });
  expect(screen.queryByText('Checks and limits')).not.toBeInTheDocument();
});
