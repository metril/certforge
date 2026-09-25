import { http, HttpResponse } from 'msw';
import { screen } from '@testing-library/react';
import { expect, it } from 'vitest';
import { server } from '@/test/server';
import { meWith, org, org2, url } from '@/test/fixtures';
import { renderRoute } from '@/test/render';

function as(bindings: Parameters<typeof meWith>[0]) {
  server.use(
    http.get(url('/setup/status'), () => HttpResponse.json({ needsSetup: false })),
    http.get(url('/auth/me'), () => HttpResponse.json(meWith(bindings, [org, org2]))),
  );
}

it('offers All orgs to a global binding', async () => {
  as([{ role: 'admin', orgId: null }]);
  const { user } = renderRoute('/o/acme/overview');
  await user.click(await screen.findByRole('button', { name: 'Organization: Acme' }));
  expect(await screen.findByRole('menuitem', { name: 'All orgs' })).toHaveAttribute('href', '/o/all/overview');
});

it('hides All orgs without a global binding', async () => {
  as([{ role: 'viewer', orgId: org.id }, { role: 'operator', orgId: org2.id }]);
  const { user } = renderRoute('/o/acme/overview');
  await user.click(await screen.findByRole('button', { name: 'Organization: Acme' }));
  await screen.findByRole('menuitem', { name: 'Lab' });
  expect(screen.queryByRole('menuitem', { name: 'All orgs' })).not.toBeInTheDocument();
});
